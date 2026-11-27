/**
 * The browser-safe half of the gateway: configuration of the parts that need no Node API (limits, named endpoints,
 * the features a host advertises), and the per-connection core that serves `OpenEndpoint`, `GatewayData`,
 * `GatewayCredit` and `GatewayClose` with flow control (`src/gateway-channel.mjs`). A host in a page
 * (`createMemoryHost({ endpoints })`) is built from this alone; `gateway.mjs` (Node: TCP, DNS, UDP, unix sockets)
 * extends it. Nothing here imports a Node built-in.
 */

import { MSG, gatewayOk, gatewayFail, gatewayClose, gatewayData, gatewayCredit, listenFail } from '../messages.gen.mjs';
import { GatewayChannel, GATEWAY_CREDIT_FEATURE, GATEWAY_LOSSLESS_FEATURE, GATEWAY_CREDIT_WINDOW, DEFAULT_HALF_CLOSE_IDLE_MS, assertHalfCloseIdleMs, assertHalfCloseProbeMs } from '../gateway-channel.mjs';

import { GATEWAY_FAIL } from '../gateway-errors.mjs';

/** Numeric codes of GatewayFail: the table of `gateway-errors.mjs` (what `@johnhenry/browsermesh-netway` decodes), under its old name here. */
export { GATEWAY_FAIL };

export const DEFAULT_MAX_CONNECTIONS = 32;
export const DEFAULT_MAX_BUFFERED = 4 * 1024 * 1024;
export const DEFAULT_MAX_CLIENT_BUFFERED = 32 * 1024 * 1024;
export const MAX_DATA_BYTES = 1024 * 1024;
import { ENDPOINT_NAME_RE, normalizeEndpoints } from './gateway-features.mjs';
export { ENDPOINT_NAME_RE };

/** The limits shared by every gateway (validated here so the Node and the in-page host agree). */
export function normalizeGatewayLimits(opts) {
  const maxConnections = opts.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isInteger(maxConnections) || maxConnections < 1) throw new TypeError('gateway.maxConnections must be a positive integer');
  const maxBufferedBytes = opts.maxBufferedBytes ?? DEFAULT_MAX_BUFFERED;
  const maxClientBufferedBytes = opts.maxClientBufferedBytes ?? DEFAULT_MAX_CLIENT_BUFFERED;
  if (!Number.isInteger(maxBufferedBytes) || maxBufferedBytes < GATEWAY_CREDIT_WINDOW) throw new TypeError(`gateway.maxBufferedBytes must be an integer of at least ${GATEWAY_CREDIT_WINDOW}`);
  if (!Number.isInteger(maxClientBufferedBytes) || maxClientBufferedBytes < maxBufferedBytes) throw new TypeError('gateway.maxClientBufferedBytes must be an integer of at least maxBufferedBytes');
  const halfCloseIdleMs = assertHalfCloseIdleMs(opts.halfCloseIdleMs, 'gateway.halfCloseIdleMs');
  // How often a socket of this host (an origin, a listener's accepted connection) whose peer half-closed is checked for a peer
  // that went away (#282). Only sockets use it; a host with none (the memory host) validates and ignores it.
  const halfCloseProbeMs = assertHalfCloseProbeMs(opts.halfCloseProbeMs, 'gateway.halfCloseProbeMs');
  // #286: `losslessClose: false` does not state `gateway-lossless-close` (the connection then behaves as it did before the feature);
  // `halfCloseProbeAnswers: false` keeps the answering side of a connection (an origin the host dialled) unwatched even where the feature is negotiated.
  const flag = (v, what) => { if (v !== undefined && typeof v !== 'boolean') throw new TypeError(`${what} must be a boolean`); return v !== false; };
  const losslessClose = flag(opts.losslessClose, 'gateway.losslessClose');
  const halfCloseProbeAnswers = flag(opts.halfCloseProbeAnswers, 'gateway.halfCloseProbeAnswers');
  // #286: the keep-alive schedule of a half-closed answering socket on ANOTHER machine (default 30 s; 0 = the short one of halfCloseProbeMs)
  const halfCloseProbeRemoteMs = opts.halfCloseProbeRemoteMs === undefined ? 30_000 : assertHalfCloseProbeMs(opts.halfCloseProbeRemoteMs, 'gateway.halfCloseProbeRemoteMs');
  return { maxConnections, maxBufferedBytes, maxClientBufferedBytes, halfCloseIdleMs, halfCloseProbeMs, losslessClose, halfCloseProbeAnswers, halfCloseProbeRemoteMs };
}

export { normalizeEndpoints } from './gateway-features.mjs';

/**
 * The configuration of a gateway that serves named endpoints only (no TCP, DNS or unix sockets): what
 * `createMemoryHost({ endpoints })` passes as `gateway`, with `createEndpointGatewaySession` as the session factory.
 */
export function normalizeEndpointGateway(opts = {}) {
  return { ...normalizeGatewayLimits(opts), tcp: false, unix: null, endpoints: normalizeEndpoints(opts.endpoints) };
}

export { gatewayFeatures } from './gateway-features.mjs';

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
  /** Both ends stated `gateway-lossless-close` (#286): this host's connections may be released, and a `released` close is understood. */
  let lossless = false;
  let closed = false;
  const budget = { used: 0, max: cfg.maxClientBufferedBytes };

  const reply = (m) => { try { return Promise.resolve(send(m)).catch(() => {}); } catch { return Promise.resolve(); } };
  const fail = (gatewayId, code, message) => reply(gatewayFail({ gatewayId, code, message }));
  const active = () => conns.size + pending.size;
  const idInUse = (id) => conns.has(id) || pending.has(id);

  /** A channel wired to the wire; `extra` adds the sink (a socket's writer) and the close hooks. */
  function makeChannel(id, extra) {
    return new GatewayChannel({
      id, credit, lossless, maxQueued: cfg.maxBufferedBytes, budget, halfCloseIdleMs: cfg.halfCloseIdleMs ?? DEFAULT_HALF_CLOSE_IDLE_MS,
      sendData: (data) => reply(gatewayData({ gatewayId: id, data })),
      sendCredit: (n) => reply(gatewayCredit({ gatewayId: id, bytes: n })),
      sendClose: (reason) => reply(gatewayClose({ gatewayId: id, reason })),
      ...extra,
      onClose: (reason, graceful) => { conns.delete(id); extra?.onClose?.(reason, graceful); },
    });
  }

  async function openEndpoint(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.name !== 'string') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenEndpoint');
    if (idInUse(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    // Execution targets (#121): a named target has its own endpoints, and the host decides (`ctx.target`) whether the caller
    // may use it; the answer for a target that does not exist and one that is refused is the same. Without a target, the host's own.
    let endpoints = cfg.endpoints;
    if (m.target !== undefined && m.target !== null) {
      const t = ctx.target ? await ctx.target(m.target) : { refuse: 'this host has no targets' };
      if (t.refuse) return fail(id, GATEWAY_FAIL.POLICY_DENIED, t.refuse);
      endpoints = t.endpoints;
    } else if (ctx.requireTarget?.()) {
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'a target is required');
    }
    const ep = endpoints && ENDPOINT_NAME_RE.test(m.name) ? endpoints.get(m.name) : undefined;
    if (!ep) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'no such endpoint');
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    const who = ctx.who?.() ?? { username: null, fingerprint: null };
    pending.add(id);
    try {
      if (ep.authorize && !(await ep.authorize(who))) { pending.delete(id); return await fail(id, GATEWAY_FAIL.POLICY_DENIED, 'endpoint refused this caller'); }
    } catch (e) { pending.delete(id); log(`gateway endpoint ${m.name} authorize threw: ${e.message}`); return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'endpoint refused this caller'); }
    pending.delete(id);
    if (closed) return undefined;
    const channel = makeChannel(id, { writeAfterRemoteClose: true, ...(ep.halfCloseIdleMs === undefined ? {} : { halfCloseIdleMs: ep.halfCloseIdleMs }) });
    conns.set(id, { channel, sock: null });
    const { readable, writable } = channel.streams();
    const duplex = {
      readable, writable, who,
      /** The execution target this endpoint belongs to (#121); undefined for the host's own. */
      target: m.target ?? undefined,
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
    setPeerFeatures(features) {
      credit = Array.isArray(features) && features.includes(GATEWAY_CREDIT_FEATURE);
      lossless = cfg.losslessClose !== false && Array.isArray(features) && features.includes(GATEWAY_LOSSLESS_FEATURE);
    },
    /** Both ends stated `gateway-lossless-close` (#286). */
    get lossless() { return lossless; },
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
    /**
     * The grant behind this connection ran out (#297): every open gateway connection is ended, the peer is told with `reason` and then,
     * as a side that lost its reader does, with "discarded" (a peer that knows it frees the connection at once; one that predates it sees
     * the first as an ordinary half-close and ignores the second). What is queued for the peer is not waited for: an expiry is a cut.
     * The connection itself and its later requests are the caller's (they are refused as expired).
     */
    endAll(reason) {
      for (const { channel } of [...conns.values()]) { channel.end(reason); channel.destroy(); }
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
