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
