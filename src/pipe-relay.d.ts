/** A WebSocket-like duplex: the `ws` package's, a browser's, or a Worker's. */
export interface PipeSocket {
  send(data: Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
  readonly readyState: number;
  readonly bufferedAmount?: number;
  pause?(): void;
  resume?(): void;
  on?(event: string, listener: (...args: any[]) => void): unknown;
  addEventListener?(event: string, listener: (ev: any) => void): unknown;
}

export interface PipeRelayOptions {
  /** Halves waiting for a partner, over all ids (default 1024). */
  maxWaiting?: number;
  /** How long a half waits for its partner (default 120000). */
  rendezvousTimeoutMs?: number;
  /** A pipe that carried no byte either way for this long is closed (default 300000). */
  idleTimeoutMs?: number;
  /** A pipe is closed this long after pairing (default 12 hours). */
  maxLifetimeMs?: number;
  /** Total bytes copied per pipe, both directions (default 1 GiB). */
  maxBytes?: number;
  /** Largest single message (default 4 MiB). */
  maxMessageBytes?: number;
  /** What a half may send before its partner arrives (default 64 KiB). */
  earlyBytes?: number;
  /** Outgoing buffer size past which the sender is paused (default 1 MiB). */
  highWaterBytes?: number;
  /** Optional gate before a half may wait or pair; default: anyone holding a well-formed id. */
  authorize?: (who: { id: string; role: 'host' | 'operator'; remote?: object }) => boolean | Promise<boolean>;
  onLog?: (line: string) => void;
}

export interface PipeRelay {
  /** Hand the relay one accepted connection; resolves false when it was refused (and closed). */
  accept(socket: PipeSocket, who: { id: string; role?: 'host' | 'operator'; remote?: object }): Promise<boolean>;
  /** Listen for WebSocket upgrades on `<path>/<id>` (default `/r`); `?role=host` is the host side. Needs the `ws` package. */
  listen(options?: { host?: string; port?: number; path?: string; tls?: object }): Promise<{ port: number; address: string; close(): Promise<void> }>;
  close(): Promise<void>;
  stats(): { waiting: number; pipes: number };
  newRendezvousId(): string;
}

export function createPipeRelay(options?: PipeRelayOptions): PipeRelay;
/** A fresh 128-bit rendezvous id, base64url. */
export function newRendezvousId(): string;
/** The URL one side dials: `<relay>/r/<id>`, with `?role=host` for the host. */
export function pipeUrl(relayUrl: string, id: string, role?: 'host' | 'operator'): string;
