/**
 * `@johnhenry/wsh/gateway`: the gateway of a wsh host over a network the embedder supplies (#299). No Node types are involved: a page, a Worker,
 * Deno, Bun and Node all take it.
 */
import type { WshServerGatewayOptions, WshReverseHostGateway } from './server/index.js';

/** The bytes of one connection, as web streams: what `connectTcp`, `openUdp` and a listener's `onConnection` hand to / take from wsh. */
export interface WshNetworkDuplex {
  /** What the far end sends. A chunk is bytes (a `Uint8Array`, an `ArrayBuffer`, or a view). Ending it is the far end's half-close. wsh reads one chunk at a time and not while the client is not reading, so this stream's own backpressure reaches the origin. */
  readable: ReadableStream<Uint8Array>;
  /** What wsh sends. Each write resolves when the far end has taken the bytes (wsh does not queue more than the gateway's credit and buffer bounds). Closing it is wsh's half-close; aborting it is wsh giving the connection up. */
  writable: WritableStream<Uint8Array>;
}

/**
 * The network a gateway dials (#299). Every method is optional (one is required); a feature whose method is absent is refused with a reason that says so.
 * None is called until a client asked and wsh's destination policy has passed. An error thrown (or rejected) is reported to the caller by its `code`: a number of
 * `GATEWAY_FAIL` (1 refused, 2 unreachable, 3 name not found, 8 timeout) or a Node-style name (`ECONNREFUSED`, `ENOTFOUND`, `ETIMEDOUT`); anything else is "unreachable".
 *
 * Every `signal` is aborted when wsh is done with what it was given: the caller closed the connection or went away, the host closed, a timeout. Release the connection or listener then.
 */
export interface WshGatewayNetwork {
  /**
   * Open a TCP-like connection to `host:port`. `host` is ALWAYS an IP address: the one `resolve` answered with that wsh's policy permitted, or the literal the caller gave
   * (checked). The name the caller used is never passed on, so there is nothing to look up twice.
   */
  connectTcp?(request: { host: string; port: number; signal: AbortSignal }): Promise<WshNetworkDuplex>;
  /**
   * The IP addresses of `name`, for `family` 4, 6 or 0 (either). Answers that are not IP addresses are ignored; wsh classifies the rest (public, private, loopback, ...)
   * and refuses what its policy does not permit BEFORE anything is dialled. This is the only place a name is turned into an address.
   */
  resolve?(request: { name: string; family: 0 | 4 | 6; signal: AbortSignal }): Promise<Array<string | { address: string }>>;
  /** Open a UDP flow to `host:port` (an IP address, as for `connectTcp`). Each chunk read or written is one datagram. */
  openUdp?(request: { host: string; port: number; signal: AbortSignal }): Promise<WshNetworkDuplex>;
  /**
   * Listen on `bindAddr:port` of the network (the address and port wsh's reverse-tunnel policy chose) and call `onConnection(duplex, { peerAddr, peerPort })` for each
   * connection that arrives. Resolves with the port it listens on (for `port: 0`) and a way to stop.
   */
  listenTcp?(request: {
    port: number;
    bindAddr: string;
    signal: AbortSignal;
    onConnection: (duplex: WshNetworkDuplex, peer: { peerAddr: string; peerPort: number }) => void;
  }): Promise<{ port: number; close?(): void | Promise<void> }>;
}

/**
 * The gateway of a host with an injected network: the options of `createWshServer({ gateway })` that make sense without a machine (`socks`, `unix`, `tcp` do not),
 * with `allow` REQUIRED (an empty list reaches nothing) and `network` added. `udp`, `dns` and `reverse` are each OFF unless given, and also need the network's
 * `openUdp`, `resolve` and `listenTcp`.
 */
export interface WshNetworkGatewayOptions extends Omit<WshServerGatewayOptions, 'socks' | 'unix' | 'endpoints' | 'tcp' | 'udp'> {
  network: WshGatewayNetwork;
  /** Destinations a client may reach: `"*"`, `"host"` (any port), `"host:port"`. An address of the network's that is not public (private, loopback, ...) is refused unless `allowPrivate` names it or an entry is that IP literal: `"*"` does not. */
  allow: string[];
  /** UDP flows (`OpenUdp`): `true` or the bounds. Off unless given. */
  udp?: boolean | NonNullable<WshServerGatewayOptions['udp']>;
  /** Name resolution for the caller (`ResolveDns`): answers are filtered by the same policy. Off unless `true`. */
  dns?: boolean;
}

/** Options of the browser-safe reverse host's gateway: the reverse host's (`trustRelayIdentity`, `udp`, `dns`, `reverse`, ...) with the network. */
export interface WshNetworkReverseGatewayOptions extends Omit<WshReverseHostGateway, 'socks'> {
  network: WshGatewayNetwork;
}

/** Validate `gateway.network` (a `TypeError` for anything but an object of functions with at least one of the four); returns it. */
export function normalizeNetwork(network: unknown): WshGatewayNetwork | null;
/** Validate and normalise a gateway configuration (the options of `createWshServer({ gateway })`, or `WshNetworkGatewayOptions`). Returns the configuration `createGatewaySession` and `createConnectionFactory` take. */
export function normalizeGateway(options: unknown): any;
/** The per-connection session: serves the gateway opcodes of one client over the configuration's network. For `createConnectionFactory({ gateway, createGatewaySession })`. */
export function createGatewaySession(cfg: any, send: (message: any) => unknown, log?: (line: string) => void, ctx?: object): any;
export function gatewayFeatures(cfg: any): string[];
export function destinationAllowed(allow: string[], host: string, port: number): boolean;
export function addressPermitted(cfg: any, address: string, options?: { explicitLiteral?: string | null }): boolean;
export function gatewayPolicy(cfg: any, explicitLiteral?: string | null): { allow: any[] };
export function normalizeReverse(options: unknown): any;
export function reversePortAllowed(reverse: any, port: number): boolean;
export function normalizeUdp(options: unknown): any;
export function parseSocks(socks: unknown): { host: string; port: number } | null;

/** The codes of `GatewayFail`, by name. */
export const GATEWAY_FAIL: Readonly<{
  CONNECTION_REFUSED: 1; HOST_UNREACHABLE: 2; DNS_FAILED: 3; POLICY_DENIED: 4; GATEWAY_DISABLED: 5; CLOSED: 6; QUEUE_FULL: 7; TIMEOUT: 8;
}>;
export const GATEWAY_FAIL_TABLE: ReadonlyArray<Readonly<{ name: string; code: number; meaning: string; alsoSentAs?: readonly string[] }>>;
export function gatewayFailName(code: number): string | null;
