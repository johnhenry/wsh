/**
 * Type-only fixture: `@johnhenry/wsh/server` must resolve by its published
 * subpath (exports map `types` condition) and type the documented surface.
 */
import { createWshServer, type WshServer, type WshServerOptions } from '@johnhenry/wsh/server';
import { sign, verify } from '@johnhenry/wsh';

const options: WshServerOptions = {
  port: 0,
  auth: { authorizedKeys: 'ssh-ed25519 AAAA', authorize: async ({ username }) => username === 'alice' },
  exec: { timeoutMs: 1000 },
  fs: { root: '/tmp', readOnly: true },
  hostKey: { file: '/tmp/host_key' },
};
const pwOptions: WshServerOptions = {
  auth: { password: async (u, p) => u === p, rateLimit: { maxFailures: 3, key: ({ address }) => address ?? '' } },
  hostKey: true,
};
const mcpOptions: WshServerOptions = {
  mcp: {
    tools: [{ name: 'echo', inputSchema: { type: 'object' }, call: (args, { user, signal }) => ({ user, args, aborted: signal.aborted }) }],
    authorize: (user, tool) => user === 'alice' && tool.name !== 'secret',
    maxConcurrent: 4,
    timeoutMs: 1000,
  },
};
const server: WshServer = createWshServer(options);
const bound: Promise<{ address: string; port: number }> = server.listen();
const maybe: { address: string; port: number } | null = server.address();
const closed: Promise<void> = server.close();
const hk: { fingerprint: string; publicKey: Uint8Array; openssh: string } | null = server.hostKey();

declare const key: CryptoKey;
const sig: Promise<Uint8Array> = sign(key, new Uint8Array(1));
const ok: Promise<boolean> = verify(key, new Uint8Array(64), new Uint8Array(1));
export { mcpOptions, bound, maybe, closed, sig, ok, pwOptions, hk };
