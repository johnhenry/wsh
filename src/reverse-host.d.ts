import type { WshExecRunner, WshServerPtyOptions, WshServerMcpOptions, WshReverseHostOptions, WshReverseHost, WshClientEnv } from './server/index.js';
import type { WshFileBackend } from './host.js';

export type { WshReverseHost } from './server/index.js';

/**
 * Options of the browser-safe `createReverseHost`: those of `@johnhenry/wsh/server`'s, with the backends that need
 * Node taken out (`exec: true` and `fs: { root }`).
 */
export interface WshBrowserReverseHostOptions extends Omit<WshReverseHostOptions, 'exec' | 'fs' | 'pty' | 'mcp'> {
  /** `run(command, io)` or `{ run }`: there is no shell in a browser to run `true` with. */
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: WshClientEnv };
  /** `node-pty`-shaped `{ spawn }`, injected. Input arrives at `write` as a `Uint8Array`. */
  pty?: WshServerPtyOptions;
  /** An object of file operations, not a root path. */
  fs?: WshFileBackend;
  mcp?: WshServerMcpOptions;
  /** Typed rpc channels (#191): one handler per protocol, served to the bridged operator in virtual data mode and stated as `rpc-virtual` in `ReverseAccept.features` (so it needs `reportFeatures`). Handler functions only. */
  rpc?: Record<string, ((channel: import('./index.js').RpcChannel, ctx: import('./server/index.js').WshRpcContext) => void | Promise<void>) | false | null | undefined>;
  rpcMaxMessageBytes?: number;
  rpcMaxInflight?: number;
}

/**
 * A host that dials OUT to a relay (`createWshServer({ relay })`) and serves the operator it bridges to it, in a page
 * or a Worker: `createReverseHost` of `@johnhenry/wsh/server` without the Node-only backends, so it imports nothing from
 * `node:*`. The relay needs the page's WebSocket (`connect` options are the client's).
 */
export function createReverseHost(options: WshBrowserReverseHostOptions): WshReverseHost;
