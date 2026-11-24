/**
 * `@johnhenry/wsh/testing`: the QMux record and frame codec primitives, for tests that look inside a connection, change it and
 * re-wrap it.
 *
 * @experimental This entry point is not part of the stable API: a release may rename, change or remove anything in it, and the
 * compatibility policy does not cover it. Application code should use the other entry points.
 */

/** QUIC variable-length integer (RFC 9000 section 16), as bytes. */
export function encodeVarint(value: number | bigint): Uint8Array;
export function decodeVarint(data: Uint8Array, offset?: number): { value: number | bigint; length: number };
export function varintLength(value: number | bigint): number;

export const FRAME_TYPE: Readonly<Record<string, number>>;
export const QX_TRANSPORT_PARAMETERS_TYPE: bigint;
export const QMUX_ERROR_CODE: Readonly<Record<string, number>>;
export const TRANSPORT_PARAM_ID: Readonly<Record<string, number>>;

/** One QMux Record: a varint size, then the frames. */
export function encodeRecord(framesBytes: Uint8Array): Uint8Array;
/** Accumulates transport bytes and yields the Frames payload of each complete record. */
export class RecordDecoder {
  feed(chunk: Uint8Array): Uint8Array[];
  reset(): void;
}
/** Decode every frame in a Frames payload; throws a `QMuxProtocolError` on a malformed one. */
export function decodeFrames(data: Uint8Array): Array<{ frameType: string; [field: string]: unknown }>;

export function encodePadding(length: number): Uint8Array;
/** A STREAM frame with Offset and Length always present. */
export function encodeStream(frame: { streamId: number | bigint; offset: number | bigint; data: Uint8Array; fin?: boolean }): Uint8Array;
export function encodeResetStream(frame: { streamId: number | bigint; errorCode: number | bigint; finalSize: number | bigint }): Uint8Array;
export function encodeResetStreamAt(frame: { streamId: number | bigint; errorCode: number | bigint; finalSize: number | bigint; reliableSize: number | bigint }): Uint8Array;
export function encodeStopSending(frame: { streamId: number | bigint; errorCode: number | bigint }): Uint8Array;
export function encodeMaxData(maxData: number | bigint): Uint8Array;
export function encodeMaxStreamData(frame: { streamId: number | bigint; maxStreamData: number | bigint }): Uint8Array;
export function encodeMaxStreams(frame: { unidirectional: boolean; maxStreams: number | bigint }): Uint8Array;
export function encodeDataBlocked(dataLimit: number | bigint): Uint8Array;
export function encodeStreamDataBlocked(frame: { streamId: number | bigint; streamDataLimit: number | bigint }): Uint8Array;
export function encodeStreamsBlocked(frame: { unidirectional: boolean; streamLimit: number | bigint }): Uint8Array;
export function encodeConnectionClose(frame: { application?: boolean; errorCode: number | bigint; frameType?: number | bigint; reason?: string }): Uint8Array;
export function encodeDatagram(data: Uint8Array): Uint8Array;
export function encodeTransportParameters(params: Record<string, unknown>): Uint8Array;

export class QMuxProtocolError extends Error {
  readonly errorCode: number;
}

import type { WshClient } from './index.js';
import type { WshMemoryHost, WshMemoryHostOptions, WshMemoryConnectOptions } from './memory-host.js';
import type { PipeRelay, PipeRelayOptions } from './pipe-relay.js';

/** One message the in-process relay wrote. */
export interface RelayTapInfo { to: 'host' | 'operator'; id: string; bytes: Uint8Array }

/** A pipe relay that lives in this process (see `createInProcessPipeRelay`). */
export interface InProcessPipeRelay {
  /** The real relay (`createPipeRelay()`); `accept` is wired to the sockets `WebSocket` hands out. */
  relay: PipeRelay;
  /** Every message the relay wrote, before `tap` ran: `to` is the role it was written to. */
  recorded: Array<{ to: 'host' | 'operator'; id: string; bytes: Uint8Array }>;
  /** Called for each message the relay writes: `undefined` passes it, `null` drops it, bytes (or an array of them) are written instead. May be set at any time. */
  tap: ((info: RelayTapInfo) => Uint8Array | Uint8Array[] | null | undefined) | null;
  /** A `WebSocket` constructor that dials this relay: `new env.WebSocket(pipeUrl(anyBase, id, role))`. */
  WebSocket: new (url: string) => any;
  stats(): { waiting: number; pipes: number };
  /** End every pipe at once, as a relay restart would. */
  dropAll(): void;
  close(): Promise<void>;
}

/** The real pipe relay running in this process, with a record and a tap for a hostile one. No port, no Node built-in. */
export function createInProcessPipeRelay(options?: { tap?: InProcessPipeRelay['tap']; relayOptions?: PipeRelayOptions }): Promise<InProcessPipeRelay>;

export interface MemoryPair {
  host: WshMemoryHost;
  client: WshClient;
  username: string;
  /** The key the client logged in with (`null` when `host.auth` was given and the client logs in some other way). */
  keyPair: CryptoKeyPair | null;
  /** Disconnects the client, then closes the host. */
  close(): Promise<void>;
}

/** A memory host and a client already logged in to it. Without `host.auth`, it makes (or uses) a key and authorizes exactly that key. */
export function createMemoryPair(options?: {
  host?: WshMemoryHostOptions;
  username?: string;
  keyPair?: CryptoKeyPair;
  credentials?: Partial<WshMemoryConnectOptions>;
}): Promise<MemoryPair>;

/** Machine-readable form of the notice: `stable` is `false`. */
export const QMUX_TESTING_API: Readonly<{ stable: false; notice: string }>;
