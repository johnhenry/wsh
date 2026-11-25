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
  /**
   * Make a rendezvous id single-use (#240): once its pipe has paired, the id is remembered and any later arrival with it, in either role,
   * is refused with 1008 `PIPE_CLOSE_REASONS.idRetired`, while the pipe lives and after it ended. Default `false`: an id can be used again
   * after its pipe paired (a page host that redials the same id relies on that). An id that never paired (a half that timed out or left) is
   * not retired. The memory this takes is bounded by `maxRetired`.
   */
  retirePaired?: boolean;
  /**
   * With `retirePaired`: the most retired ids remembered (default 10000, a positive integer; about a megabyte). When it is full the OLDEST is
   * forgotten, and that id can be used again. Ignored when `retirePaired` is off.
   */
  maxRetired?: number;
  /** Optional gate before a half may wait or pair; default: anyone holding a well-formed id. `authorize` runs before the retired check. */
  authorize?: (who: { id: string; role: 'host' | 'operator'; remote?: object }) => boolean | Promise<boolean>;
  onLog?: (line: string) => void;
}

export interface PipeRelay {
  /** Hand the relay one accepted connection; resolves false when it was refused (and closed). */
  accept(socket: PipeSocket, who: { id: string; role?: 'host' | 'operator'; remote?: object; notifyPaired?: boolean }): Promise<boolean>;
  /**
   * Listen for WebSocket upgrades on `<path>/<id>` (default `/r`); `?role=host` is the host side, `&paired=1` asks to be told when the
   * operator arrives. Node only, and needs the `ws` package: the code that does it is loaded when this is called, so the rest of this
   * module bundles for a browser.
   */
  listen(options?: { host?: string; port?: number; path?: string; tls?: object }): Promise<{ port: number; address: string; close(): Promise<void> }>;
  close(): Promise<void>;
  /** `retired`: the ids `retirePaired` remembers right now (0 when it is off). */
  stats(): { waiting: number; pipes: number; retired: number };
  newRendezvousId(): string;
}

/**
 * The close reason texts a relay sends (#240), a stable list: new texts may be added, none is renamed. Each limit closes BOTH halves of a
 * pipe with the same code and the same text; `peerClosed` is the one text that means the partner's own socket went away.
 */
export const PIPE_CLOSE_REASONS: Readonly<{
  peerClosed: 'peer closed';
  noPartner: 'no partner arrived';
  idle: 'idle';
  lifetime: 'maximum lifetime reached';
  byteLimit: 'byte limit reached';
  messageTooLarge: 'message too large';
  binaryOnly: 'binary messages only';
  earlyOverflow: 'too much before the partner arrived';
  receiverTooSlow: 'receiver too slow';
  sendFailed: 'send failed';
  shuttingDown: 'relay is shutting down';
  badId: 'bad rendezvous id';
  badRole: 'bad role';
  notPermitted: 'not permitted';
  idInUse: 'rendezvous id in use';
  idRetired: 'rendezvous id already used';
  tooManyWaiting: 'too many waiting connections';
}>;

export function createPipeRelay(options?: PipeRelayOptions): PipeRelay;
/** A fresh 128-bit rendezvous id, base64url. */
export function newRendezvousId(): string;
/**
 * The URL one side dials: `<relay>/r/<id>`, with `?role=host` for the host. `notifyPaired` (host only) adds `&paired=1`: ask the relay to
 * send `PAIRED_FRAME` when the operator arrives; a relay that predates it ignores the parameter.
 */
export function pipeUrl(relayUrl: string, id: string, role?: 'host' | 'operator', options?: { notifyPaired?: boolean }): string;
/** The one text frame a relay sends a host that asked, when its partner arrives, before anything the partner said. */
export const PAIRED_FRAME: 'wsh-pipe/1 paired';
/**
 * Host side of the paired signal: wrap the socket the host dialled (with `notifyPaired`) before anything is attached, pass `socket` on to
 * `accept()`, await `paired`. It resolves when the operator arrives and rejects if the socket closes first; the signal frame is kept out
 * of what the wsh host reads. Against a relay that does not know the flag it never resolves and the connection works as before.
 */
export function watchPairing<S extends object>(socket: S): { socket: S; paired: Promise<void> };
