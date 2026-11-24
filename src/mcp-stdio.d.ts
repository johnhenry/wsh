// `@johnhenry/wsh/mcp-stdio` (wsh #127): the stdio bridge behind the `wsh-mcp` command. Node only.

import type { WshClient } from './index.js';

/** A failure the bridge cannot recover from. `exitCode` is what the `wsh-mcp` command exits with (2: could not start). */
export class McpBridgeError extends Error {
  constructor(message: string, options?: { code?: string; exitCode?: number; cause?: unknown });
  /** `connect`, `auth`, `no-channel`, `identity`, `replay` or `bridge`. */
  code: string;
  exitCode: number;
}

/** `~/.wsh/keys/default.pem`, the key `wsh keygen` makes. */
export function defaultIdentityPath(): string;

/**
 * Read an Ed25519 private key file (`-----BEGIN WSH PRIVATE KEY-----`, the 32-byte secret in base64, or a PKCS#8 PEM) as a
 * signer for `WshClient.connect({ signer })`.
 */
export function loadIdentity(file: string): Promise<{ publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> }>;

export interface McpStdioBridgeOptions {
  /** `ws://`, `wss://` or `https://` URL of the wsh host. */
  url: string;
  username: string;
  signer: { publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> };
  /** The rpc protocol to open. Default `'mcp'`. */
  channel?: string;
  /** Pin the host: a hex fingerprint, a raw key or an `ssh-ed25519` line. */
  expectHostKey?: string | Uint8Array;
  /** `true` seals the whole session end to end and refuses a host that cannot (key login only); the `--sealed` flag. Default: the client's `'auto'`. */
  sealSession?: boolean | 'auto';
  /** After a lost connection: attempts (default 5), first delay in ms (500, doubling) and the longest delay (10000); `false` to exit instead. */
  reconnect?: false | { attempts?: number; delayMs?: number; maxDelayMs?: number };
  /** To log in and to open the channel, ms. Default 15000. */
  timeoutMs?: number;
  /** Longest message accepted from the client, bytes. Default 8 MiB. */
  maxLineBytes?: number;
  /** Messages held while reconnecting. Default 200. */
  maxQueued?: number;
  /** Newline-delimited JSON-RPC from the MCP client. Default `process.stdin`. */
  input?: AsyncIterable<Uint8Array | string>;
  /** MCP messages to the client, one JSON-RPC message per line; nothing else is ever written here. Default `process.stdout`. */
  output?: { write(chunk: string): unknown };
  /** Diagnostics. Default `process.stderr`. */
  errorOutput?: { write(chunk: string): unknown };
  clientFactory?: () => WshClient;
  /** Set `close` to end the bridge from outside (a signal handler). */
  signalHandle?: { close: (() => Promise<void>) | null } | null;
}

/**
 * Bridge `input` / `output` to the `mcp` channel of a wsh host. Resolves with the exit status (0: the client closed its side;
 * 1: the host was lost for good); rejects with an `McpBridgeError` when it cannot start.
 */
export function runMcpStdioBridge(options: McpStdioBridgeOptions): Promise<number>;
