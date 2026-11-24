/** Type-only fixture for #220: `@johnhenry/wsh/duplex`. Run by `npm run typecheck`. */
import { createDuplexSocket, serveWshOverDuplex, connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import { createMemoryHost } from '@johnhenry/wsh/memory';

export async function over(keyPair: CryptoKeyPair, expectHostKey: string): Promise<void> {
  const host = createMemoryHost({ hostKey: true, dataStreams: false });
  const served = serveWshOverDuplex(host, { send: (bytes: Uint8Array) => { void bytes; }, maxMessageBytes: 4096 });
  served.receive(new Uint8Array(1));
  await served.ready;
  const link = connectWshOverDuplex({ send: async () => {}, close: () => {} }, { username: 'alice', keyPair, expectHostKey, timeout: 5000 });
  const client = await link.connected;
  const state: string = client.state;
  link.end('gone');
  await link.close();
  const socket = createDuplexSocket({ send() {} });
  void [state, socket.closed];
}
