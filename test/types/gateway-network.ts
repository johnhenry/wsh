/** Type-only fixture: the gateway over a network the embedder supplies (#299): `createMemoryHost({ gateway })`, the browser-safe reverse host, and `@johnhenry/wsh/gateway`. */
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createReverseHost } from '@johnhenry/wsh/reverse';
import { createWshServer } from '@johnhenry/wsh/server';
import { normalizeGateway, createGatewaySession, GATEWAY_FAIL, type WshGatewayNetwork, type WshNetworkDuplex } from '@johnhenry/wsh/gateway';

const pipe = new TransformStream<Uint8Array, Uint8Array>();
const duplex: WshNetworkDuplex = { readable: pipe.readable, writable: pipe.writable };

const network: WshGatewayNetwork = {
  async connectTcp({ host, port, signal }) { void [host.length, port + 1, signal.aborted]; return duplex; },
  async resolve({ name, family, signal }) { void [name, family === 4, signal]; return ['10.0.0.5', { address: '10.0.0.6' }]; },
  async openUdp({ host, port, signal }) { void [host, port, signal]; return duplex; },
  async listenTcp({ port, bindAddr, signal, onConnection }) {
    void [port, bindAddr, signal];
    onConnection(duplex, { peerAddr: '10.0.0.9', peerPort: 5555 });
    return { port: 9000, close() {} };
  },
};

const host = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' },
  endpoints: { docker: (d) => { d.destroy(); } },
  gateway: { network, allow: ['db.internal:5432'], allowPrivate: ['10.0.0.0/8'], udp: { maxFlows: 4 }, dns: true, reverse: { ports: [0, '9000-9100'] }, maxConnections: 8, connectTimeoutMs: 5000 },
});
void host;

const reverse = createReverseHost({
  url: 'wss://relay.example', username: 'host', keyPair: {} as CryptoKeyPair,
  gateway: { network, allow: ['*'], trustRelayIdentity: true, udp: true, dns: true },
});
void reverse;

const server = createWshServer({ gateway: { network, allow: ['10.0.0.5:80'], allowPrivate: ['10.0.0.0/8'] } });
void server;

const cfg = normalizeGateway({ network, allow: [] });
const session = createGatewaySession(cfg, () => undefined);
void [session, GATEWAY_FAIL.POLICY_DENIED];
