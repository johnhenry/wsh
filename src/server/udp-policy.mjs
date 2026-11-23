/**
 * Bounds of the Node host's UDP flows (`gateway.udp`, #98 / #124). A UDP flow is a socket the host opens on the client's
 * behalf, to ONE destination fixed at `OpenUdp`, so the risks are the host being used as a packet cannon and as an
 * amplifier: a small query that makes a big answer, repeated. Everything is therefore rate-limited in both directions
 * and bounded in count. Browser-safe (pure).
 *
 *  - `datagrams` (default true): use WebTransport datagrams for a flow when the transport and the peer have them.
 *  - `maxFlows` (16): concurrent UDP flows per client (they also count against `maxConnections`).
 *  - `packetsPerSecondPerFlow` (500) and `packetsPerSecondPerClient` (2000): token buckets over datagrams in BOTH
 *    directions; a datagram over the limit is dropped (and counted), as a congested network would.
 *  - `bytesPerSecondPerClient` (4 MiB): the same over payload bytes in both directions. This is what bounds
 *    amplification: no matter how many bytes an origin answers with, no more than this reach the client per second.
 *  - `oversize` ('reliable'): a payload from the origin that does not fit one datagram goes on the reliable control
 *    stream rather than being lost; 'drop' drops it (strict UDP semantics) and counts it.
 */

export const DEFAULT_UDP = Object.freeze({
  datagrams: true,
  maxFlows: 16,
  packetsPerSecondPerFlow: 500,
  packetsPerSecondPerClient: 2000,
  bytesPerSecondPerClient: 4 * 1024 * 1024,
  oversize: 'reliable',
});

const rate = (v, what) => {
  if (v === Infinity) return v;
  if (!Number.isFinite(v) || v <= 0) throw new TypeError(`gateway.udp.${what} must be a positive number (or Infinity for no limit)`);
  return v;
};

/** @param {unknown} opts `gateway.udp` (`undefined` = the defaults) */
export function normalizeUdp(opts) {
  if (opts === undefined || opts === null || opts === true) opts = {};
  if (typeof opts !== 'object' || Array.isArray(opts)) throw new TypeError('gateway.udp must be an options object');
  const maxFlows = opts.maxFlows ?? DEFAULT_UDP.maxFlows;
  if (!Number.isInteger(maxFlows) || maxFlows < 0) throw new TypeError('gateway.udp.maxFlows must be a non-negative integer');
  const oversize = opts.oversize ?? DEFAULT_UDP.oversize;
  if (oversize !== 'reliable' && oversize !== 'drop') throw new TypeError('gateway.udp.oversize must be "reliable" or "drop"');
  return {
    datagrams: opts.datagrams !== false,
    maxFlows,
    packetsPerSecondPerFlow: rate(opts.packetsPerSecondPerFlow ?? DEFAULT_UDP.packetsPerSecondPerFlow, 'packetsPerSecondPerFlow'),
    packetsPerSecondPerClient: rate(opts.packetsPerSecondPerClient ?? DEFAULT_UDP.packetsPerSecondPerClient, 'packetsPerSecondPerClient'),
    bytesPerSecondPerClient: rate(opts.bytesPerSecondPerClient ?? DEFAULT_UDP.bytesPerSecondPerClient, 'bytesPerSecondPerClient'),
    oversize,
  };
}

/** A fresh counter set (one per gateway configuration, shared by its client connections). */
export function newGatewayStats() {
  return {
    udp: {
      flowsOpened: 0, datagramsFromClient: 0, datagramsToClient: 0, reliableFromClient: 0, reliableToClient: 0,
      oversizeReliable: 0, oversizeDropped: 0, rateDropped: 0, backpressureDropped: 0, unknownFlow: 0, malformed: 0,
    },
    reverse: { listeners: 0, accepted: 0, refusedConnections: 0, idleClosed: 0 },
  };
}
