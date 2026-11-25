/**
 * `@johnhenry/wsh/address-guard`: the gateway's destination-address guard as a public entry point (Node).
 * The classifier functions (`isPublicAddress`, `classifyAddress`, `checkAddress`, `ADDRESS_CLASSES`) are pure and do not
 * touch Node: a bundler can take them alone.
 */
import type { Socket } from 'node:net';
import type { Socket as DgramSocket } from 'node:dgram';

/** What an address is: `public` (globally routable unicast) or the reason it is not. `invalid` is anything that is not an IP address. */
export type AddressClass =
  | 'public'
  | 'invalid'
  | 'unspecified'
  | 'loopback'
  | 'private'
  | 'unique-local'
  | 'link-local'
  | 'metadata'
  | 'carrier-nat'
  | 'documentation'
  | 'benchmarking'
  | 'multicast'
  | 'teredo'
  | 'reserved';

/** Every class `classifyAddress` can return. */
export const ADDRESS_CLASSES: readonly AddressClass[];

/** Is this address globally routable unicast? An IPv6 address that wraps an IPv4 one (mapped, NAT64, 6to4) is judged as that IPv4 address. Not an address: false. */
export function isPublicAddress(ip: string): boolean;

/** What kind of address is this? An IPv4-mapped, NAT64 or 6to4 address is classified as the IPv4 address it wraps; Teredo (`2001::/32`) is `teredo`. */
export function classifyAddress(ip: string): AddressClass;

/** Which destinations may be dialled. */
export interface AddressPolicy {
  /** Let the private-network classes through (`private`, `loopback`, `link-local`, `unique-local`, `carrier-nat`). Never `metadata`, `unspecified`, `multicast`, `reserved`, `documentation`, `benchmarking` or `teredo`. Default false. */
  allowPrivate?: boolean;
  /** CIDR blocks or single addresses (`"10.0.0.0/8"`, `"127.0.0.1"`, `"fd00::/8"`) that are permitted whatever their class. */
  allow?: readonly string[];
  /** CIDR blocks or addresses that are always refused, public ones included. Wins over `allow` and `allowPrivate`; also refuses the mapped, NAT64 and 6to4 forms of an IPv4 block. */
  deny?: readonly string[];
}

export interface AddressCheck {
  permitted: boolean;
  class: AddressClass;
  /** Present when `permitted` is false: refused by its class, or by the `deny` list. */
  reason?: 'class' | 'deny';
}

/** May an address be dialled under a policy? A bad policy entry throws a `TypeError`. */
export function checkAddress(ip: string, policy?: AddressPolicy): AddressCheck;

export type AddressGuardErrorCode =
  | 'ADDRESS_REFUSED'
  | 'NAME_NOT_FOUND'
  | 'LOOKUP_FAILED'
  | 'CONNECTION_REFUSED'
  | 'UNREACHABLE'
  | 'TIMEOUT'
  | 'ABORTED';

/** What went wrong in a resolve or dial. `refused` is set for `ADDRESS_REFUSED`. */
export class AddressGuardError extends Error {
  readonly name: 'AddressGuardError';
  readonly code: AddressGuardErrorCode;
  /** The addresses the policy refused, with their class (for `ADDRESS_REFUSED`). */
  readonly refused?: ReadonlyArray<{ address: string; class: AddressClass }>;
  readonly refusedAddresses?: readonly string[];
  readonly cause?: unknown;
}

export interface ResolveOptions extends AddressPolicy {
  /** Resolve and keep this family only (default 0: both). */
  family?: 0 | 4 | 6;
  /** Bounds the lookup, and for a dial the connects, together. Default 15000. */
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Refuse the whole name when ANY answer is refused, instead of dropping the refused ones. Default false. */
  refuseMixed?: boolean;
  /** The resolver, called once per name (default: `dns.lookup` with every answer, in resolver order). */
  lookup?: (name: string, options: { family: 0 | 4 | 6 }) => Promise<ReadonlyArray<string | { address: string; family?: number }>>;
}

export interface CheckedAddress {
  address: string;
  family: 4 | 6;
  class: AddressClass;
}

/** Resolve a name once and return the addresses the policy permits (an IP literal is checked as it is). Rejects `ADDRESS_REFUSED` when none is permitted. */
export function resolveChecked(name: string, options?: ResolveOptions): Promise<CheckedAddress[]>;

export interface CheckedSocket<S> extends CheckedAddress {
  socket: S;
}

/** Resolve once, check, and connect a TCP socket to an address that passed (never to the name). Reports the address dialled. */
export function dialChecked(host: string, port: number, options?: ResolveOptions): Promise<CheckedSocket<Socket>>;

/** The same for a UDP socket, `connect()`ed to the checked address: datagrams from any other address or port are dropped by the kernel. */
export function dialUdpChecked(host: string, port: number, options?: ResolveOptions): Promise<CheckedSocket<DgramSocket>>;
