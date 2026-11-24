/**
 * `@johnhenry/wsh/capabilities`: the notation of key capabilities as a pure function. The notation is written in
 * `spec/capabilities.md` and its vectors in `spec/capabilities.vectors.json` (both in the package, under `@johnhenry/wsh/spec/`).
 * Browser-safe (no Node import); a stable entry point.
 */

/** A request a capability list is asked about; the kinds, and what each needs, are in `spec/capabilities.md`. */
export type CapabilityRequest =
  | { kind: 'login' }
  | { kind: 'open'; channel: 'pty' | 'exec'; target?: string }
  | { kind: 'open'; channel: 'file'; direction: 'upload' | 'download'; target?: string }
  | { kind: 'open'; channel: 'rpc'; protocol: string; scoped?: boolean; target?: string }
  | { kind: 'file-op'; op: string; target?: string }
  | { kind: 'mcp' }
  | { kind: 'mcp-call' | 'mcp-tool'; tool: string }
  | { kind: 'objects'; root: string; op: 'get' | 'call' | 'set' | 'on' | 'walk' }
  | { kind: 'relay' }
  | { kind: 'key-admin' }
  | { kind: 'tcp' | 'udp'; host: string; port: number }
  | { kind: 'dns'; name: string }
  | { kind: 'listen-tcp'; port: number }
  | { kind: 'unix' | 'listen-unix'; path: string }
  | { kind: 'endpoint'; name: string; target?: string }
  | { kind: 'target'; name: string };

export interface CapabilityRefusal {
  /** `capability-missing` (see `capability`), `key-expired`, `key-admin-not-permitted`, or `unknown-capability` / `bad-capability` for a list with an entry that is not understood (the whole list is refused). */
  code: string;
  reason: string;
  /** The capability that was needed, for `capability-missing`. */
  capability?: string;
}

export interface CapabilityOptions {
  /** An RFC 3339 string, a `Date` or epoch milliseconds: the instant from which the list is refused. */
  expires?: string | Date | number;
  /** A `Date` or epoch milliseconds (default: the present). */
  now?: Date | number;
}

/** The revision of the notation implemented here: the `version` of `spec/capabilities.vectors.json`. */
export const CAPABILITIES_NOTATION_VERSION: 1;

/** Parse a capability list; `{ ok: false, code, reason }` for an entry that is unknown or malformed. */
export function parseCapabilityList(list: string | string[]):
  | { ok: true; capabilities: string[]; parsed: object[] }
  | { ok: false; code: string; reason: string };

/** `null` when a holder of `capabilities` may make `request`, else why not. Fails closed. */
export function checkCapabilities(capabilities: string[] | string, request: CapabilityRequest, options?: CapabilityOptions): CapabilityRefusal | null;

/** Whether a holder of `capabilities` may make `request`. A list with an entry that is not understood, no list, or an unknown request kind permits nothing. */
export function permits(capabilities: string[] | string, request: CapabilityRequest, options?: CapabilityOptions): boolean;
