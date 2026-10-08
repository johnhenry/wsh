/**
 * Type-only fixture: `@johnhenry/wsh/server` must resolve by its published
 * subpath (exports map `types` condition) and type the documented surface.
 */
import { createWshServer, createReverseHost, generateSelfSignedCertificate, type WshServer, type WshServerOptions, type WshReverseHost } from '@johnhenry/wsh/server';
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
const tlsOptions: WshServerOptions = {
  tls: { cert: 'PEM', key: 'PEM' },
  extensions: { push_subscribe: (msg, { username, fingerprint, send }) => { void [msg, username, fingerprint, send]; } },
  relay: { onUnreachable: (from, target, request) => { void [from.fingerprint, target, request.username]; } },
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
const wtOptions: WshServerOptions = { webTransport: { port: 4433, path: '/wsh', selfSigned: { hosts: ['localhost'], validityDays: 7 } } };
const wtOwnCert: WshServerOptions = { webTransport: { cert: 'pem', privKey: 'pem', host: '0.0.0.0' } };
const wtInfo: { url: string; certificateHash: Uint8Array | null } | null = createWshServer(wtOptions).webTransport();
const wtRotation: WshServerOptions = { webTransport: { selfSigned: { rotate: true, prepareBeforeMs: 1000, activateBeforeMs: 500 } } };
const pins: { algorithm: 'sha-256'; value: Uint8Array }[] = createWshServer(wtOptions).certificateHashes();
const rotated: Promise<{ current: { hashHex: string; active: boolean }; next: { notAfter: Date } | null }> = createWshServer(wtOptions).rotateCertificate({ activate: true });
const selfSigned: { cert: string; privKey: string; hash: Uint8Array; notAfter: Date } = generateSelfSignedCertificate({ validityDays: 3 });
const server: WshServer = createWshServer(options);
const bound: Promise<{ address: string; port: number }> = server.listen();
const maybe: { address: string; port: number } | null = server.address();
const closed: Promise<void> = server.close();
const hk: { fingerprint: string; publicKey: Uint8Array; openssh: string } | null = server.hostKey();

declare const key: CryptoKey;
const sig: Promise<Uint8Array> = sign(key, new Uint8Array(1));
const ok: Promise<boolean> = verify(key, new Uint8Array(64), new Uint8Array(1));
export { wtRotation, pins, rotated, wtOptions, wtOwnCert, wtInfo, selfSigned, relayOptions, reverse, peers, sessionOptions, sessionsOn, mcpOptions, bound, maybe, closed, sig, ok, pwOptions, hk };
