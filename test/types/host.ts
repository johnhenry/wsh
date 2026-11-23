/** Type-only fixture: the browser-safe entry points `@johnhenry/wsh/host` and `/reverse`, and the injected backends of `/memory` (#114, #115). */
import { createMemoryHost, type WshMemoryHost } from '@johnhenry/wsh/memory';
import { createConnectionFactory, bindSocket, resolveBackends, resolveHostKey, buildAuthorizer, authMethods, type WshFileBackend } from '@johnhenry/wsh/host';
import { createReverseHost } from '@johnhenry/wsh/reverse';

const fs: WshFileBackend = {
  async operate(op, path) { return { metadata: { op, path } }; },
  async readWhole() { return new Uint8Array(0); },
  async writeWhole() {},
  async writeAt() {},
};
declare const keyPair: CryptoKeyPair;

const host: WshMemoryHost = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' },
  exec: async (command, io) => { await io.write(command); return 0; },
  pty: { spawn: () => ({ onData() {}, onExit() {}, write(_d: string | Uint8Array) {}, resize() {}, kill() {} }) },
  fs,
  hostKey: keyPair,
  dataStreams: false,
});
void host.accept({ send() {}, close() {}, readyState: 1, addEventListener() {} }, { dataStreams: true });
createMemoryHost({ hostKey: { publicKey: new Uint8Array(32), sign: async (d) => d } });
createMemoryHost({ hostKey: true });

async function wire() {
  const backends = resolveBackends({ exec: async () => 0, fs });
  const auth = { authorizedKeys: 'ssh-ed25519 AAAA' };
  const attach = createConnectionFactory({ authorize: await buildAuthorizer(auth), methods: authMethods(auth), hostKey: await resolveHostKey(keyPair), ...backends });
  const conn = attach({ send(_bytes: Uint8Array) {}, dataStreams: false });
  conn.receive(new Uint8Array(0));
  void bindSocket({ send() {}, close() {}, readyState: 1, addEventListener() {} }, Promise.resolve(attach));
}
void wire;

const reverse = createReverseHost({ url: 'wss://relay.example/', username: 'me', keyPair, exec: async () => 0, fs, pty: { spawn: () => { throw new Error('no'); } } });
void reverse.start();
// @ts-expect-error `exec: true` needs a shell: not offered by the browser-safe reverse host
createReverseHost({ url: 'wss://relay.example/', username: 'me', keyPair, exec: true });
