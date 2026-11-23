/**
 * The client half of gateway forwarding: `openUnix`, `openEndpoint`, `openTcp` and `listenUnix` on `WshClient`.
 * Browser-safe (no `node:*`): the connections are web streams with backpressure (see `gateway-channel.mjs`);
 * `forward-node.mjs` builds the Node helper `client.forwardUnix()` on top.
 *
 * gateway_ids and listener_ids this client allocates start at 0x40000000, so they cannot collide with the small
 * ids an application that drives the raw gateway messages itself (netway's `GatewayBackend`) hands out; messages for
 * ids this class does not own go on to `client.onGatewayMessage`.
 */

import {
  MSG, openTcp as openTcpMsg, openUdp as openUdpMsg, listenRequest as listenRequestMsg, openUnix as openUnixMsg, openEndpoint as openEndpointMsg, listenUnix as listenUnixMsg,
  listenClose as listenCloseMsg, inboundAccept as inboundAcceptMsg, inboundReject as inboundRejectMsg,
  gatewayData as gatewayDataMsg, gatewayCredit as gatewayCreditMsg, gatewayClose as gatewayCloseMsg,
} from './messages.mjs';
import { GatewayChannel, GATEWAY_CREDIT_FEATURE } from './gateway-channel.mjs';
import { UdpFlow, decodeDatagram } from './gateway-datagram.mjs';

const ID_BASE = 0x40000000;
const ID_LIMIT = 0xffffffff;
const DEFAULT_TIMEOUT_MS = 30_000;
const CLIENT_GRACE_MS = 5_000;

/** An Error from a GatewayFail / ListenFail: `.code` is the GatewayFail code (4 = refused by policy), `.reason` the host's text. */
export class GatewayError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'GatewayError';
    this.code = code;
  }
}

/**
 * @typedef {object} GatewayDuplex
 * @property {ReadableStream<Uint8Array>} readable  what the peer sends; read it to keep the peer's credit coming
 * @property {WritableStream<Uint8Array>} writable  what you send; each write waits for credit
 * @property {(reason?: string) => void} close  half-close: nothing more will be written
 * @property {(reason?: string) => void} destroy  tear the connection down now
 * @property {Promise<string | undefined>} closed  settles when the connection is over
 */

export class GatewayConnections {
  #send;
  #hasFeature;
  #nextId = ID_BASE;
  /** @type {Map<number, GatewayChannel>} */
  #channels = new Map();
  /** @type {Map<number, { channel: GatewayChannel, resolve: Function, reject: Function, timer: any }>} */
  #opening = new Map();
  /** @type {Map<number, { onConnection: Function, resolve?: Function, reject?: Function, timer?: any, path: string, closed: boolean }>} */
  #listeners = new Map();

  /**
   * @param {object} o
   * @param {(msg: object) => Promise<void>} o.send
   * @param {(feature: string) => boolean} o.hasFeature
   */
  constructor({ send, hasFeature, datagrams = () => null }) {
    this.#send = send;
    this.#hasFeature = hasFeature;
    this.#datagrams = datagrams;
  }

  #datagrams;
  /** @type {Map<number, UdpFlow>} */
  #udp = new Map();

  /** A WebTransport datagram arrived: [gateway_id][payload]. A flow we do not have is dropped, as a stray datagram is. */
  handleDatagram(bytes) {
    const d = decodeDatagram(bytes);
    if (d) this.#udp.get(d.id)?.deliverDatagram(d.payload);
  }

  #id() {
    if (this.#nextId >= ID_LIMIT) throw new Error('gateway ids exhausted on this connection');
    return this.#nextId++;
  }

  #need(feature, what) {
    if (!this.#hasFeature(feature)) throw new GatewayError(`this host does not support ${what} (it did not advertise "${feature}")`, 0);
  }

  /** @param {{ datagram?: boolean, onData?: (bytes: Uint8Array) => void }} [kind] a datagram flow has no half-close: the peer's close ends it */
  #makeChannel(id, { datagram = false, onData } = {}) {
    const channel = new GatewayChannel({
      id,
      credit: this.#hasFeature(GATEWAY_CREDIT_FEATURE),
      // After the peer's GatewayClose the application has this long to finish writing (a half-open connection) before
      // our side closes too, so a connection nobody closes does not stay in the table forever.
      graceMs: CLIENT_GRACE_MS,
      onRemoteClose: datagram ? () => channel.destroy() : undefined,
      onData,
      sendData: (data) => this.#send(gatewayDataMsg({ gatewayId: id, data })),
      sendCredit: (n) => this.#send(gatewayCreditMsg({ gatewayId: id, bytes: n })),
      sendClose: (reason) => this.#send(gatewayCloseMsg({ gatewayId: id, reason })),
      onClose: () => { this.#channels.delete(id); this.#udp.delete(id); },
    });
    this.#channels.set(id, channel);
    return channel;
  }

  #duplex(channel) {
    const flow = this.#udp.get(channel.id);
    if (flow) return flow;
    const { readable, writable } = channel.streams();
    return { readable, writable, close: (r) => channel.end(r), destroy: (r) => channel.destroy(r), closed: channel.closedPromise };
  }

  async #open(build, { timeoutMs = DEFAULT_TIMEOUT_MS, signal } = {}, kind) {
    if (signal?.aborted) throw signal.reason ?? new DOMException('aborted', 'AbortError');
    const id = this.#id();
    let flow;
    const channel = this.#makeChannel(id, { ...kind, onData: kind?.udp ? (b) => flow.deliverReliable(b) : undefined });
    if (kind?.udp) { flow = new UdpFlow({ id, channel, ...kind.udp }); this.#udp.set(id, flow); }
    const done = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.#opening.delete(id); channel.abandon(); reject(new GatewayError('the host did not answer the open request in time', 5)); }, timeoutMs);
      timer.unref?.();
      this.#opening.set(id, { channel, resolve, reject, timer });
    });
    const onAbort = () => {
      const o = this.#opening.get(id);
      if (!o) return;
      this.#opening.delete(id); clearTimeout(o.timer);
      channel.destroy(); // the host's Ok, if it comes, finds nothing; its connection is closed by this GatewayClose
      o.reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      await this.#send(build(id));
    } catch (e) {
      const o = this.#opening.get(id);
      if (o) { clearTimeout(o.timer); this.#opening.delete(id); }
      channel.abandon();
      throw e;
    }
    try { return await done; } finally { signal?.removeEventListener('abort', onAbort); }
  }

  /** Connect to a unix-domain socket on the HOST. */
  async openUnix(path, opts) {
    this.#need('gateway-unix', 'unix-domain socket forwarding');
    if (typeof path !== 'string' || !path) throw new TypeError('openUnix: path must be a non-empty string');
    return this.#open((id) => openUnixMsg({ gatewayId: id, path }), opts);
  }

  /** Open a named virtual endpoint of the host. */
  async openEndpoint(name, opts) {
    this.#need('gateway-endpoints', 'named endpoints');
    if (typeof name !== 'string' || !name) throw new TypeError('openEndpoint: name must be a non-empty string');
    return this.#open((id) => openEndpointMsg({ gatewayId: id, name }), opts);
  }

  /** Connect to host:port FROM THE HOST (the gateway's TCP egress, subject to the host's allow list). */
  async openTcp(host, port, opts) {
    this.#need('gateway', 'TCP egress');
    if (typeof host !== 'string' || !host || !Number.isInteger(port)) throw new TypeError('openTcp: host and port are required');
    return this.#open((id) => openTcpMsg({ gatewayId: id, host, port }), opts);
  }

  /**
   * A UDP "connection" to host:port FROM THE HOST: each chunk written is one datagram, each chunk read is one datagram
   * (at most 65507 bytes). It rides the reliable control stream, so it is ordered and retransmitted; datagrams the
   * receiving side cannot keep up with are dropped by the host. Same destination policy as TCP.
   */
  async openUdp(host, port, opts) {
    this.#need('gateway', 'UDP egress');
    if (typeof host !== 'string' || !host || !Number.isInteger(port)) throw new TypeError('openUdp: host and port are required');
    if (opts?.oversize !== undefined && opts.oversize !== 'reliable' && opts.oversize !== 'drop') throw new TypeError('openUdp: oversize must be "reliable" or "drop"');
    // Whether this flow uses datagrams is fixed at open: both ends negotiated it for the connection.
    const datagrams = this.#datagrams();
    return this.#open((id) => openUdpMsg({ gatewayId: id, host, port }), opts, {
      datagram: true,
      udp: { datagrams, oversize: opts?.oversize },
    });
  }

  /**
   * Ask the host to listen on a TCP port (a reverse tunnel) and hand each inbound connection to `onConnection(duplex, { peer, peerPort })`.
   * @param {number} port @param {{ bindAddr?: string, onConnection: Function, timeoutMs?: number }} opts
   * @returns {Promise<{ port: number, close: () => Promise<void> }>}
   */
  async listenTcp(port, { bindAddr, onConnection, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.#need('gateway', 'reverse tunnels (ListenRequest)');
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError('listenTcp: port must be an integer 0-65535');
    if (typeof onConnection !== 'function') throw new TypeError('listenTcp: onConnection is required');
    const id = this.#id();
    const entry = { onConnection, path: '', closed: false, actualPort: 0 };
    const answered = new Promise((resolve, reject) => {
      entry.resolve = resolve; entry.reject = reject;
      entry.timer = setTimeout(() => { this.#listeners.delete(id); reject(new GatewayError('the host did not answer the listen request in time', 5)); }, timeoutMs);
      entry.timer.unref?.();
    });
    this.#listeners.set(id, entry);
    try {
      await this.#send(listenRequestMsg({ listenerId: id, port, ...(bindAddr === undefined ? {} : { bindAddr }) }));
      await answered;
    } catch (e) { this.#listeners.delete(id); throw e; }
    return {
      port: entry.actualPort,
      close: async () => {
        if (entry.closed) return;
        entry.closed = true;
        this.#listeners.delete(id);
        await this.#send(listenCloseMsg({ listenerId: id })).catch(() => {});
      },
    };
  }

  /**
   * Ask the host to listen on a unix-domain socket and hand each connection to `onConnection(duplex)`.
   * @param {string} path
   * @param {{ replace?: boolean, onConnection: (duplex: GatewayDuplex) => void, timeoutMs?: number }} opts
   * @returns {Promise<{ path: string, close: () => Promise<void> }>}
   */
  async listenUnix(path, { replace, onConnection, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.#need('gateway-unix', 'unix-domain socket forwarding');
    if (typeof path !== 'string' || !path) throw new TypeError('listenUnix: path must be a non-empty string');
    if (typeof onConnection !== 'function') throw new TypeError('listenUnix: onConnection is required');
    const id = this.#id();
    const entry = { onConnection, path, closed: false };
    const answered = new Promise((resolve, reject) => {
      entry.resolve = resolve; entry.reject = reject;
      entry.timer = setTimeout(() => { this.#listeners.delete(id); reject(new GatewayError('the host did not answer the listen request in time', 5)); }, timeoutMs);
      entry.timer.unref?.();
    });
    this.#listeners.set(id, entry);
    try {
      await this.#send(listenUnixMsg({ listenerId: id, path, replace: replace === true ? true : undefined }));
      await answered;
    } catch (e) { this.#listeners.delete(id); throw e; }
    return {
      path,
      close: async () => {
        if (entry.closed) return;
        entry.closed = true;
        this.#listeners.delete(id);
        await this.#send(listenCloseMsg({ listenerId: id })).catch(() => {});
      },
    };
  }

  /** Feed a control message in. Returns true when it belonged to a connection or listener this object owns. */
  handle(m) {
    switch (m.type) {
      case MSG.GATEWAY_OK: {
        const o = this.#opening.get(m.gateway_id);
        if (!o) return this.#channels.has(m.gateway_id);
        this.#opening.delete(m.gateway_id);
        clearTimeout(o.timer);
        o.resolve(this.#duplex(o.channel));
        return true;
      }
      case MSG.GATEWAY_FAIL: {
        const o = this.#opening.get(m.gateway_id);
        if (!o) return false;
        this.#opening.delete(m.gateway_id);
        clearTimeout(o.timer);
        o.channel.abandon();
        o.reject(new GatewayError(m.message || 'refused by the host', m.code));
        return true;
      }
      case MSG.GATEWAY_DATA: { const c = this.#channels.get(m.gateway_id); if (!c) return false; c.receive(m.data); return true; }
      case MSG.GATEWAY_CREDIT: { const c = this.#channels.get(m.gateway_id); if (!c) return false; c.grant(m.bytes); return true; }
      case MSG.GATEWAY_CLOSE: {
        const c = this.#channels.get(m.gateway_id);
        if (!c) return false;
        const o = this.#opening.get(m.gateway_id);
        if (o) { this.#opening.delete(m.gateway_id); clearTimeout(o.timer); c.abandon(); o.reject(new GatewayError('closed by the host', 6)); return true; }
        c.remoteClosed(m.reason);
        return true;
      }
      case MSG.LISTEN_OK: { const l = this.#listeners.get(m.listener_id); if (!l?.resolve) return false; clearTimeout(l.timer); l.actualPort = m.actual_port; l.resolve(); l.resolve = undefined; return true; }
      case MSG.LISTEN_FAIL: {
        const l = this.#listeners.get(m.listener_id);
        if (!l?.reject) return false;
        clearTimeout(l.timer);
        this.#listeners.delete(m.listener_id);
        l.reject(new GatewayError(m.reason || 'refused by the host', 4));
        return true;
      }
      case MSG.INBOUND_OPEN: {
        const l = this.#listeners.get(m.listener_id);
        if (!l) return false;
        if (l.closed) { void this.#send(inboundRejectMsg({ channelId: m.channel_id, reason: 'listener closed' })).catch(() => {}); return true; }
        let id;
        try { id = this.#id(); } catch { void this.#send(inboundRejectMsg({ channelId: m.channel_id, reason: 'out of ids' })).catch(() => {}); return true; }
        const channel = this.#makeChannel(id);
        const duplex = this.#duplex(channel);
        void this.#send(inboundAcceptMsg({ channelId: m.channel_id, gatewayId: id })).then(() => {
          try { l.onConnection(duplex, { peer: m.peer_addr, peerPort: m.peer_port }); } catch { channel.destroy('handler error'); }
        }, () => channel.abandon());
        return true;
      }
      default: return false;
    }
  }

  /** The connection is gone: every open connection ends, every pending open fails. */
  abandonAll(reason = 'connection closed') {
    for (const o of this.#opening.values()) { clearTimeout(o.timer); o.reject(new GatewayError(reason, 6)); }
    this.#opening.clear();
    for (const l of this.#listeners.values()) { clearTimeout(l.timer); l.reject?.(new GatewayError(reason, 6)); }
    this.#listeners.clear();
    for (const c of [...this.#channels.values()]) c.abandon(reason);
    this.#channels.clear();
  }
}
