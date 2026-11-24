/**
 * Test doubles for code that embeds wsh (part of `@johnhenry/wsh/testing`: NOT part of the stable API). Browser-safe: no port, no Node
 * built-in, so a test in a page or a worker can use them too.
 *
 *   - `createInProcessPipeRelay()`: the real pipe relay (`createPipeRelay`) living in this process, with a `WebSocket` constructor that
 *     dials it, a record of every message it copied, and a `tap` that may change, drop, repeat or add to what it writes (what a hostile
 *     relay could do). Two parties that dial it with the same rendezvous id are joined, and run the real handshake and sealed session.
 *   - `createMemoryPair()`: a memory host and a client already logged in to it, with a key the pair made and authorized.
 */

import { createPipeRelay } from './pipe-relay.mjs';
import { createMemoryHost, createSocketPair } from './memory-host.mjs';
import { generateKeyPair, exportPublicKeyRaw } from './auth.mjs';

const toBytes = (data) => (data instanceof ArrayBuffer
  ? new Uint8Array(data)
  : new Uint8Array(data.buffer, data.byteOffset, data.byteLength));

/**
 * A pipe relay in this process, for tests: no network, no ports.
 *
 * `new env.WebSocket(pipeUrl(anyBase, id, role))` dials it (the base is ignored; the path's last segment is the rendezvous id and
 * `?role=host` the host side). A `WshClient` takes `env.WebSocket` as its WebSocket (`new WebSocketTransport({ WebSocket: env.WebSocket })`)
 * and a host accepts the other half with `host.accept(new env.WebSocket(pipeUrl(base, id, 'host')))`.
 *
 * Every message the relay writes is recorded in `env.recorded` as `{ to: 'host' | 'operator', id, bytes }` (`to` is the role it was
 * written to), BEFORE `tap` runs. `env.tap` (set at creation or later) is called for each such message and may return `undefined` to pass
 * it through, `null` to drop it, or one `Uint8Array` or an array of them to write instead (change, repeat, add). `env.dropAll()` ends every
 * pipe at once, as a relay restart would.
 *
 * @param {object} [options]
 * @param {(info: { to: 'host' | 'operator', id: string, bytes: Uint8Array }) => (Uint8Array | Uint8Array[] | null | undefined)} [options.tap]
 * @param {object} [options.relayOptions] options of `createPipeRelay()` (limits, `authorize`, ...)
 * @returns {Promise<{ relay: object, recorded: Array<{ to: string, id: string, bytes: Uint8Array }>, tap: Function | null, WebSocket: Function, stats(): { waiting: number, pipes: number }, dropAll(): void, close(): Promise<void> }>}
 */
export async function createInProcessPipeRelay({ tap = null, relayOptions } = {}) {
  if (tap !== null && typeof tap !== 'function') throw new TypeError('createInProcessPipeRelay: tap must be a function');
  const relay = createPipeRelay(relayOptions);
  const sockets = new Set();
  const env = {
    relay,
    recorded: [],
    tap,
    stats: () => relay.stats(),
    /** End every pipe, as a relay restart would. */
    dropAll() {
      for (const s of [...sockets]) { try { s.close(1012, 'relay restarted'); } catch { /* already closed */ } }
    },
    async close() {
      env.dropAll();
      await relay.close();
    },
    WebSocket: null,
  };
  env.WebSocket = class InProcessWebSocket {
    constructor(url) {
      const u = new URL(url);
      const id = u.pathname.split('/').pop();
      const role = u.searchParams.get('role') === 'host' ? 'host' : 'operator';
      const [client, server] = createSocketPair();
      const send = server.send.bind(server);
      server.send = (data) => {
        // A text frame (the paired signal) is not wsh bytes: it is passed on as it is, and not recorded.
        if (typeof data === 'string') { send(data); return; }
        const bytes = toBytes(data);
        env.recorded.push({ to: role, id, bytes: bytes.slice() });
        let out = [bytes];
        if (env.tap) {
          const r = env.tap({ to: role, id, bytes });
          if (r === null) out = [];
          else if (r !== undefined) out = Array.isArray(r) ? r : [r];
        }
        for (const b of out) send(b);
      };
      sockets.add(server);
      server.addEventListener('close', () => sockets.delete(server));
      void relay.accept(server, { id, role, notifyPaired: role === 'host' && u.searchParams.get('paired') === '1' }).catch(() => {});
      return client;
    }
  };
  return env;
}

/**
 * A memory host and a client already logged in to it.
 *
 * With no `host.auth` it makes (or uses) an Ed25519 key and authorizes exactly that key. With `host.auth` it uses the host exactly as given,
 * and the client logs in with what you say (`keyPair`, or `credentials` such as `{ password }`).
 *
 * @param {object} [options]
 * @param {object} [options.host] options of `createMemoryHost()` (`exec`, `rpc`, `hostKey`, `sealSession`, ...)
 * @param {string} [options.username='alice']
 * @param {CryptoKeyPair} [options.keyPair] a key to log in with (made if not given); it is authorized unless `host.auth` is given
 * @param {object} [options.credentials] extra options of `host.connect()` (`password`, `timeout`, ...), merged over the key login
 * @returns {Promise<{ host: object, client: object, username: string, keyPair: CryptoKeyPair | null, close(): Promise<void> }>}
 */
export async function createMemoryPair({ host: hostOptions = {}, username = 'alice', keyPair, credentials = {} } = {}) {
  if (hostOptions === null || typeof hostOptions !== 'object') throw new TypeError('createMemoryPair: host must be the options of createMemoryHost()');
  const own = hostOptions.auth !== undefined;
  if (own && keyPair === undefined && credentials.password === undefined && credentials.signer === undefined && credentials.keyPair === undefined) {
    throw new TypeError('createMemoryPair: host.auth is given, so say how to log in: a keyPair it authorizes, or credentials ({ password } or { signer })');
  }
  const key = keyPair ?? (own ? null : await generateKeyPair(true));
  const host = createMemoryHost(own ? hostOptions : { ...hostOptions, auth: { authorizedKeys: [await exportPublicKeyRaw(key.publicKey)] } });
  let client;
  try {
    client = await host.connect({ username, ...(key ? { keyPair: key } : {}), ...credentials });
  } catch (e) { await host.close(); throw e; }
  return {
    host, client, username, keyPair: key,
    async close() {
      try { await client.disconnect(); } finally { await host.close(); }
    },
  };
}
