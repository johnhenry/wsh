/** Type-only fixture: `@johnhenry/wsh/memory` (#99) and the page-held `signer` (#100). */
import { createMemoryHost, createSocketPair, type WshMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, WebSocketTransport, type WshSigner } from '@johnhenry/wsh';

const host: WshMemoryHost = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' },
  exec: async (command, io) => { await io.write(command); return 0; },
});
const signer: WshSigner = { publicKey: new Uint8Array(32), sign: async (d) => d };
const client: Promise<WshClient> = host.connect({ username: 'demo', signer });
const t = new WebSocketTransport({ WebSocket: host.WebSocket });
const [a, b] = createSocketPair();
void [client, t, a, b, host.url];

// Named virtual endpoints (#120) and the gateway client API.
import type { WshGatewayDuplex } from '@johnhenry/wsh';
const withEndpoints = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' },
  endpoints: {
    docker: async (duplex, who) => { void who.username; await duplex.writable.getWriter().close(); },
    vip: { authorize: (who) => who.username === 'alice', open: (duplex) => { duplex.destroy(); } },
  },
});
async function gatewayTypes(c: WshClient): Promise<void> {
  const d: WshGatewayDuplex = await c.openEndpoint('docker', { signal: AbortSignal.timeout(1000) });
  const u: WshGatewayDuplex = await c.openUnix('/var/run/docker.sock');
  const l = await c.listenUnix('/run/x.sock', { replace: true, onConnection: (duplex, info) => { void [duplex.readable, info.peer]; } });
  const f = await c.forwardUnix({ local: '127.0.0.1:2375', remote: '/var/run/docker.sock' });
  void [d.closed, u.writable, l.path, f.local, withEndpoints];
  await Promise.all([l.close(), f.close()]);
}
void gatewayTypes;

/** #163: `onRefused` gets a stable reason code; `REFUSAL_REASONS` lists them. */
import { REFUSAL_REASONS, type WshRefusalReason } from '@johnhenry/wsh/host';
const refusals: WshRefusalReason[] = [];
const withRefusals: WshMemoryHost = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' },
  onRefused: ({ reason, who, detail }) => { refusals.push(reason); void [who.username, who.fingerprint, who.address, detail]; },
});
void [REFUSAL_REASONS, withRefusals];
