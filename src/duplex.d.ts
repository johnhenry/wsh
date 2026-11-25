/**
 * `@johnhenry/wsh/duplex`: a full wsh session over a duplex of messages that another library provides (a mesh channel, a `MessagePort`).
 * Browser-safe. See `spec/duplex-binding.md` for what the duplex must guarantee and what a hop can and cannot do.
 */
import type { WshClient } from './index.js';

export const DUPLEX_DEFAULT_MAX_MESSAGE_BYTES: 65536;
export const DUPLEX_DEFAULT_MAX_BUFFERED_BYTES: 4194304;

export interface WshDuplexOptions {
  /** Writes ONE message to the far side (reliable, in order). May be asynchronous: the next message waits for it. A throw or rejection ends the link. */
  send(bytes: Uint8Array): void | Promise<void>;
  /** Ends the underlying duplex (called when the session ends; not called after `end()`). */
  close?(reason?: string): void;
  /** Default 65536. A bigger write is cut into messages of at most this size; a bigger incoming message ends the link. */
  maxMessageBytes?: number;
  /** Default 4194304. Bytes waiting for `send` (or for a listener) before the link is ended. */
  maxBufferedBytes?: number;
}

/** What `createDuplexSocket` makes: a WebSocket-shaped object the transport and `host.accept` take, and the two calls that feed it. */
export function createDuplexSocket(options: WshDuplexOptions): {
  socket: object;
  /** One message from the far side. */
  receive(data: Uint8Array | ArrayBuffer): void;
  /** The duplex ended on its own. */
  end(reason?: string): void;
  readonly closed: boolean;
};

/**
 * Serve a host's session over a duplex, SEALED (the host serves nothing until the session is sealed, whatever its own `sealSession`). The host needs a
 * host key; with none `ready` rejects. `allowUnsealed: true` lifts it.
 */
export function serveWshOverDuplex(
  host: { accept(socket: object, options?: object): Promise<{ close(): void }> },
  options: WshDuplexOptions & { allowUnsealed?: boolean; remote?: { address?: string }; waitForPeer?: boolean | Promise<unknown> },
): {
  receive(data: Uint8Array | ArrayBuffer): void;
  end(reason?: string): void;
  ready: Promise<{ close(): void }>;
  close(): void;
};

/**
 * Connect a client over a duplex: key login, sealed, bound to the host key, and the host key must be named (`expectHostKey`, `knownHosts`, or
 * `trustOnFirstUse: true`). `allowUnsealed: true` lifts the seal and the binding; a password login needs it.
 */
export function connectWshOverDuplex(
  duplex: WshDuplexOptions,
  credentials: {
    username: string;
    keyPair?: CryptoKeyPair;
    signer?: { publicKey: Uint8Array | CryptoKey; sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array };
    password?: string;
    expectHostKey?: string;
    knownHosts?: object;
    trustOnFirstUse?: boolean;
    allowUnsealed?: boolean;
    timeout?: number;
    [option: string]: unknown;
  },
): {
  receive(data: Uint8Array | ArrayBuffer): void;
  end(reason?: string): void;
  client: WshClient;
  connected: Promise<WshClient>;
  close(): Promise<void>;
};
