/**
 * A reverse host: this process dials OUT to a relay (`createWshServer({ relay })`),
 * registers itself as a peer, and serves whichever operator the relay bridges to
 * it -- with the same exec / pty / fs / mcp backends `createWshServer` serves
 * direct clients with. Use it for a machine that cannot accept connections.
 *
 * The relay has already authenticated the operator (its key), so the bridged
 * connection is pre-authenticated; what a relay-asserted identity is worth is
 * yours to decide in `accept`, which defaults to refusing everyone.
 */

import { WshClient } from '../client.mjs';
import { exportPublicKeyRaw, fingerprint } from '../auth.mjs';
import { reverseAccept, reverseReject } from '../messages.gen.mjs';
import { buildBackends } from './backends.mjs';
import { createConnectionFactory } from './connection.mjs';

const BACKOFF_START_MS = 500;
const BACKOFF_MAX_MS = 30_000;

/**
 * @param {object} options
 * @param {string} options.url - The relay (`ws://` or `wss://`).
 * @param {string} options.username
 * @param {CryptoKeyPair} options.keyPair - This host's identity; its fingerprint is what operators connect to.
 * @param {(operator: { fingerprint: string, username: string }) => boolean | Promise<boolean>} [options.accept]
 *   Who may be bridged to this host. Default: nobody.
 * @param {true | object | Function} [options.exec]
 * @param {object} [options.pty]
 * @param {object} [options.fs]
 * @param {object} [options.mcp]
 * @param {boolean} [options.reconnect=true] - Dial again (with backoff) after the relay connection ends. A relay ends it when a bridge does.
 * @param {object} [options.connect] - Extra options for the relay connection (`expectHostKey`, `knownHosts`, ...).
 * @param {string} [options.peerType='host']
 * @param {(line: string) => void} [options.onLog]
 */
export function createReverseHost({
  url, username, keyPair, accept, exec, pty, fs, mcp, reconnect = true, connect = {}, peerType = 'host', onLog = () => {},
} = {}) {
  if (!url) throw new TypeError('createReverseHost: url is required');
  if (!username) throw new TypeError('createReverseHost: username is required');
  if (!keyPair) throw new TypeError('createReverseHost: keyPair is required (the relay keys peers by fingerprint)');
  if (accept !== undefined && typeof accept !== 'function') throw new TypeError('createReverseHost: accept must be a function');

  const backends = buildBackends({ exec, pty, fs, mcp });
  const expose = { shell: !!backends.pty, exec: !!backends.execRunner, fs: !!backends.files, tools: !!backends.mcp };
  const capabilities = Object.entries(expose).filter(([, on]) => on).map(([k]) => k);
  const shellBackend = backends.pty ? 'pty' : 'exec-only';
  const factory = createConnectionFactory({
    authorize: async () => false, methods: { pubkey: false, password: null }, hostKey: null, rateLimit: null,
    execRunner: backends.execRunner, execOptions: backends.execOptions, pty: backends.pty, files: backends.files, mcp: backends.mcp,
    sessions: null, relay: null, bindTimeoutMs: 3000, log: (l) => onLog(`[reverse] ${l}`),
  });

  let client = null;
  let myFingerprint = null;
  let closed = false;
  let timer = null;
  let backoff = BACKOFF_START_MS;

  async function dial() {
    const c = new WshClient();
    let bridge = null;
    let operator = null;

    const endBridge = () => {
      if (operator) c.untrustRelayPeer(operator);
      bridge?.close();
      bridge = null;
      operator = null;
    };
    c.onRelayMessage = (msg) => bridge?.receiveMessage(msg);
    c.onReverseConnect = async (req) => {
      const from = req.from_fingerprint;
      const answer = (m) => c.sendRelayControl(m).catch(() => {});
      const refuse = (reason) => answer(reverseReject({ targetFingerprint: myFingerprint, username, reason }));
      if (bridge || typeof from !== 'string' || !from) { await refuse('busy'); return; }
      let ok = false;
      try { ok = (await accept?.({ fingerprint: from, username: String(req.username ?? '') })) === true; } catch (e) { onLog(`[reverse] accept threw: ${e.message}`); }
      if (!ok || bridge) { await refuse('not accepted'); return; }
      c.trustRelayPeer(from);
      operator = from;
      bridge = factory({
        sendMessage: (m) => c.sendRelayControl(m),
        authenticated: { username: String(req.username ?? 'operator'), fingerprint: from },
        dataStreams: false,
      });
      onLog(`[reverse] bridged to ${from.slice(0, 12)}`);
      await answer(reverseAccept({
        targetFingerprint: myFingerprint, username, capabilities, peerType, shellBackend,
        supportsAttach: false, supportsReplay: false, supportsEcho: false, supportsTermSync: false,
      }));
    };
    c.onClose = () => {
      endBridge();
      if (client === c) client = null;
      if (closed || !reconnect) return;
      onLog(`[reverse] relay connection ended; redialling in ${backoff}ms`);
      timer = setTimeout(() => { redial().catch(() => {}); }, backoff);
      timer.unref?.();
      backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    };

    await c.connectReverse(url, {
      username, keyPair, expose, peerType, shellBackend,
      supportsAttach: false, supportsReplay: false, supportsEcho: false, supportsTermSync: false,
      ...connect,
    });
    client = c;
    backoff = BACKOFF_START_MS;
    onLog(`[reverse] registered ${myFingerprint.slice(0, 12)} on ${url}`);
  }

  async function redial() {
    if (closed) return;
    try { await dial(); } catch (e) {
      onLog(`[reverse] redial failed: ${e.message}`);
      if (closed || !reconnect) return;
      timer = setTimeout(() => { redial().catch(() => {}); }, backoff);
      timer.unref?.();
      backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    }
  }

  return {
    /** Dial the relay and register. Rejects if the first attempt fails; later drops are retried. */
    async start() {
      if (client) throw new Error('createReverseHost: already started');
      closed = false;
      myFingerprint = await fingerprint(await exportPublicKeyRaw(keyPair.publicKey));
      await dial();
      return { fingerprint: myFingerprint };
    },
    /** Leave the relay and end any bridged session. */
    async close() {
      closed = true;
      clearTimeout(timer);
      const c = client;
      client = null;
      await c?.disconnect().catch(() => {});
    },
    /** This host's fingerprint (what operators `reverseConnect()` to); `null` before `start()`. */
    get fingerprint() { return myFingerprint; },
    /** Is the relay connection up right now? */
    get connected() { return client !== null; },
  };
}
