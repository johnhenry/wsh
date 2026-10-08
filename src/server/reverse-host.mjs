/**
 * A reverse host: this process dials OUT to a relay (`createWshServer({ relay })`),
 * registers itself as a peer, and serves whichever operator the relay bridges to
 * it -- with the same exec / pty / fs / mcp backends `createWshServer` serves
 * direct clients with. Use it for a machine that cannot accept connections.
 *
 * The relay has already authenticated the operator (its key), so the bridged
 * connection is pre-authenticated; what a relay-asserted identity is worth is
 * yours to decide in `accept`, which defaults to refusing everyone.
 *
 * One operator at a time by default. With `maxOperators` > 1 (and a relay
 * configured with `relay.maxOperatorsPerPeer`) several operators are served at
 * once, each with its own connection state -- channels, processes, files -- and
 * when one leaves only what belongs to it is cleaned up (wsh #89).
 */

import { WshClient } from '../client.mjs';
import { exportPublicKeyRaw, fingerprint } from '../auth.mjs';
import { reverseAccept, reverseReject } from '../messages.gen.mjs';
import { MULTI_OPERATOR_FEATURE } from './relay.mjs';
import { E2E_SIGN_FEATURE } from '../e2e-exchange.mjs';
import { buildBackends } from './backends.mjs';
import { createConnectionFactory, hostFeatures } from './connection.mjs';

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
 * @param {false | { sign?: boolean | 'auto', hybrid?: boolean }} [options.e2e] - End-to-end encryption for the bridged operator (wsh #90).
 *   On by default: this host answers an operator's `KeyExchange` (for a session it has opened), then seals that
 *   session's output and opens its input as `EncryptedFrame`s the relay cannot read, and ignores plaintext input for it.
 *   `sign` signs the reply with `keyPair` so the operator can authenticate this host
 *   (`initiateE2E(..., { verifyPeer })`). Default `'auto'`: sign when the relay says (`e2e-sign` in its ServerHello) it
 *   carries a signed `KeyExchange` -- a relay that predates the `signature` field (a Rust relay built before it)
 *   would drop the connection on one. `true` signs regardless; `false` never does. `hybrid` (default true) offers
 *   X25519+ML-KEM-768 when asked.
 *   `false` turns the layer off: no `e2e` feature, `KeyExchange` unanswered.
 * @param {number} [options.maxOperators=1] - Operators served at once. Above 1 this host states `relay-multi-operator`
 *   (it addresses each reply to its operator and handles `ReverseClose`), so it needs `reportFeatures` and a relay with
 *   `relay.maxOperatorsPerPeer` above 1 (which says so in its ServerHello); against any other relay it serves one
 *   operator, as before. Each operator is passed through `accept` on its own identity.
 * @param {boolean} [options.reportFeatures=true] - State this host's features in `ReverseAccept.features`, so the operator's
 *   feature gates follow this host rather than the relay. Turn off only for a relay (a Rust `wsh-server` older than the field)
 *   that rejects a `ReverseAccept` carrying it.
 * @param {(line: string) => void} [options.onLog]
 */
export function createReverseHost({
  url, username, keyPair, accept, exec, pty, fs, mcp, reconnect = true, connect = {}, peerType = 'host', reportFeatures = true, maxOperators = 1, e2e = {}, onLog = () => {},
} = {}) {
  if (!url) throw new TypeError('createReverseHost: url is required');
  if (!username) throw new TypeError('createReverseHost: username is required');
  if (!keyPair) throw new TypeError('createReverseHost: keyPair is required (the relay keys peers by fingerprint)');
  if (accept !== undefined && typeof accept !== 'function') throw new TypeError('createReverseHost: accept must be a function');
  if (!Number.isSafeInteger(maxOperators) || maxOperators < 1) throw new TypeError('createReverseHost: maxOperators must be a positive integer');
  if (maxOperators > 1 && !reportFeatures) throw new TypeError('createReverseHost: maxOperators > 1 needs reportFeatures (the relay learns "relay-multi-operator" from ReverseAccept.features)');
  if (e2e !== false && (e2e === null || typeof e2e !== 'object')) throw new TypeError('createReverseHost: e2e must be false or an options object');
  const multi = maxOperators > 1;
  if (e2e !== false && e2e.sign !== undefined && e2e.sign !== 'auto' && typeof e2e.sign !== 'boolean') throw new TypeError("createReverseHost: e2e.sign must be true, false or 'auto'");
  const e2eSign = e2e === false ? false : (e2e.sign ?? 'auto');

  const backends = buildBackends({ exec, pty, fs, mcp });
  const expose = { shell: !!backends.pty, exec: !!backends.execRunner, fs: !!backends.files, tools: !!backends.mcp };
  const capabilities = Object.entries(expose).filter(([, on]) => on).map(([k]) => k);
  const shellBackend = backends.pty ? 'pty' : 'exec-only';
  // What this host can do over a bridge, for the operator's feature gates (`ReverseAccept.features`).
  // `reportFeatures: false` leaves them out (a Rust peer or relay older than the field rejects a ReverseAccept that has it).
  /** What this host does with end-to-end encryption on a given relay connection (null = off). */
  const e2eFor = (c) => (e2e === false ? null : {
    signKey: e2eSign === true || (e2eSign === 'auto' && c.hasFeature(E2E_SIGN_FEATURE)) ? keyPair.privateKey : null,
    hybrid: e2e.hybrid !== false,
  });
  /** Features for `ReverseAccept` on this relay connection. */
  const bridgeFeatures = (c, e2eConfig, manyOperators) => [
    ...hostFeatures({ mcp: backends.mcp, files: backends.files, e2e: e2eConfig }, { dataStreams: false }),
    ...(manyOperators ? [MULTI_OPERATOR_FEATURE] : []),
  ];
  const factory = createConnectionFactory({
    authorize: async () => false, methods: { pubkey: false, password: null }, hostKey: null, rateLimit: null,
    execRunner: backends.execRunner, execOptions: backends.execOptions, pty: backends.pty, files: backends.files, mcp: backends.mcp,
    sessions: null, relay: null, e2e: null, bindTimeoutMs: 3000, log: (l) => onLog(`[reverse] ${l}`),
  });

  let client = null;
  /** The live connection's bridges (operator fingerprint -> connection), for `operators`. */
  let operatorsNow = new Map();
  /** Ends every bridge of the live connection (the client's own `disconnect()` does not call its `onClose`). */
  let endAllBridges = () => {};
  let myFingerprint = null;
  let closed = false;
  let timer = null;
  let backoff = BACKOFF_START_MS;

  async function dial() {
    const c = new WshClient();
    /** operator fingerprint -> that operator's connection (its own channels, processes, files). */
    const bridges = new Map();
    // Several operators only on a relay that says it can route to them; anywhere else, one, and bare messages.
    const manyOperators = () => multi && c.hasFeature(MULTI_OPERATOR_FEATURE);
    const operatorLimit = () => (manyOperators() ? maxOperators : 1);
    /** Operators whose `accept` is still running: they count towards the cap. */
    const reserved = new Set();
    operatorsNow = bridges;

    const endBridge = (fp) => {
      const bridge = bridges.get(fp);
      if (!bridge) return;
      bridges.delete(fp);
      c.untrustRelayPeer(fp);
      bridge.close();
      onLog(`[reverse] operator ${fp.slice(0, 12)} left (${bridges.size} still bridged)`);
    };
    const endAll = () => { for (const fp of [...bridges.keys()]) endBridge(fp); };
    endAllBridges = endAll;
    c.onRelayMessage = (msg, from) => bridges.get(from)?.receiveMessage(msg);
    // The relay says one operator left; the others carry on (it sends this only to a host that stated multi-operator support).
    c.onReverseClose = (m) => endBridge(String(m.target_fingerprint ?? ''));
    c.onReverseConnect = async (req) => {
      const from = req.from_fingerprint;
      const answer = (m) => c.sendRelayControl(m).catch(() => {});
      const refuse = (reason) => answer(reverseReject({ targetFingerprint: myFingerprint, username, reason }));
      if (typeof from !== 'string' || !from) { await refuse('busy: this host is already serving an operator'); return; }
      if (bridges.has(from) || reserved.has(from)) { await refuse('busy: you already have a bridge with this host'); return; }
      if (bridges.size + reserved.size >= operatorLimit()) {
        await refuse(manyOperators() ? `busy: this host is already serving its maximum of ${maxOperators} operators` : 'busy: this host is already serving an operator');
        return;
      }
      reserved.add(from);
      let ok = false;
      try {
        try { ok = (await accept?.({ fingerprint: from, username: String(req.username ?? '') })) === true; } catch (e) { onLog(`[reverse] accept threw: ${e.message}`); }
        if (!ok || bridges.size >= operatorLimit()) { await refuse('not accepted'); return; }
        c.trustRelayPeer(from);
        const bridge = factory({
          // With several operators every message names its recipient; with one the relay knows.
          sendMessage: (m) => c.sendRelayControl(m, manyOperators() ? { to: from } : undefined),
          authenticated: { username: String(req.username ?? 'operator'), fingerprint: from },
          dataStreams: false,
          e2e: e2eFor(c),
        });
        bridges.set(from, bridge);
        onLog(`[reverse] bridged to ${from.slice(0, 12)}`);
        await answer(reverseAccept({
          targetFingerprint: myFingerprint, username, capabilities, peerType, shellBackend,
          supportsAttach: false, supportsReplay: false, supportsEcho: false, supportsTermSync: false,
          features: reportFeatures ? bridgeFeatures(c, e2eFor(c), manyOperators()) : undefined,
        }));
      } finally { reserved.delete(from); }
    };
    c.onClose = () => {
      endAll();
      if (operatorsNow === bridges) operatorsNow = new Map();
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
      endAllBridges(); // no operator's process may outlive the host
      await c?.disconnect().catch(() => {});
    },
    /** This host's fingerprint (what operators `reverseConnect()` to); `null` before `start()`. */
    get fingerprint() { return myFingerprint; },
    /** Is the relay connection up right now? */
    get connected() { return client !== null; },
    /** Fingerprints of the operators bridged right now. */
    get operators() { return [...operatorsNow.keys()]; },
  };
}
