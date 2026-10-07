/**
 * Type-only fixture: `@johnhenry/wsh/server` must resolve by its published
 * subpath (exports map `types` condition) and type the documented surface.
 */
import { createWshServer, createReverseHost, type WshServer, type WshServerOptions, type WshReverseHost } from '@johnhenry/wsh/server';
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
const sessionOptions: WshServerOptions = { sessions: { detachTtlMs: 1000, maxDetached: 4, ringBytes: 4096, sessionSecret: 'x' } };
const sessionsOn: WshServerOptions = { sessions: true, sessionSecret: new Uint8Array(32) };
const relayOptions: WshServerOptions = {
  relay: {
    canRegister: (who, record) => who.username === record.username,
    canConnect: (from, to) => from.fingerprint !== to.fingerprint && to.capabilities.includes('exec'),
    maxPeers: 10,
    connectTimeoutMs: 1000,
  },
};
declare const kp: CryptoKeyPair;
const reverse: WshReverseHost = createReverseHost({ url: 'ws://relay', username: 'host', keyPair: kp, exec: true, accept: ({ fingerprint }) => fingerprint.length > 0 });
const peers: string[] = createWshServer(relayOptions).peerFingerprints();
const server: WshServer = createWshServer(options);
const bound: Promise<{ address: string; port: number }> = server.listen();
const maybe: { address: string; port: number } | null = server.address();
const closed: Promise<void> = server.close();
const hk: { fingerprint: string; publicKey: Uint8Array; openssh: string } | null = server.hostKey();

declare const key: CryptoKey;
const sig: Promise<Uint8Array> = sign(key, new Uint8Array(1));
const ok: Promise<boolean> = verify(key, new Uint8Array(64), new Uint8Array(1));
export { relayOptions, reverse, peers, sessionOptions, sessionsOn, mcpOptions, bound, maybe, closed, sig, ok, pwOptions, hk };
