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

import { WshClient } from './client.mjs';
import { exportPublicKeyRaw, fingerprint } from './auth.mjs';
import { MSG, reverseAccept, reverseReject, reverseChallenge } from './messages.gen.mjs';
import { MULTI_OPERATOR_FEATURE } from './server/relay.mjs';
import { RELAY_GATEWAY_FEATURE } from './features.mjs';
import { GATEWAY_LOSSLESS_FEATURE, GATEWAY_LOSSLESS_ACK_FEATURE } from './gateway-channel.mjs';
import { grantPermissions } from './key-options.mjs';
import { E2E_SIGN_FEATURE, E2EResponder } from './e2e-exchange.mjs';
import { OPERATOR_PROOF_FEATURE, E2E_SEALED_FEATURE, createReverseChallenge, verifyOperatorProof } from './operator-proof.mjs';
import { SealedBridge, BRIDGE_CHANNEL_ID } from './bridge-seal.mjs';
import { resolveBackends, createRpcTable } from './host-backends.mjs';
import { RPC_DEFAULT_MAX_MESSAGE } from './rpc.mjs';
import { createConnectionFactory, hostFeatures } from './server/connection.mjs';
import { validateOnShare } from './shares.mjs';
import { refusalNotifier, validateOnRefused } from './refusal.mjs';
import { checkGatewayShape, checkReverseTrust } from './gateway-shape.mjs';

const BACKOFF_START_MS = 500;
const BACKOFF_MAX_MS = 30_000;

/**
 * @param {object} options
 * @param {string} options.url - The relay (`ws://` or `wss://`).
 * @param {string} options.username
 * @param {CryptoKeyPair} options.keyPair - This host's identity; its fingerprint is what operators connect to.
 * @param {(operator: { fingerprint: string, username: string, proven?: boolean, publicKey?: Uint8Array }) => boolean | Promise<boolean>} [options.accept]
 *   Who may be bridged to this host. Default: nobody.
 * @param {true | object | Function} [options.exec]
 * @param {object} [options.pty]
 * @param {object} [options.fs]
 * @param {object} [options.mcp]
 * @param {Record<string, Function | false | null>} [options.rpc] - Typed rpc channels (wsh #85, #191): `{ [protocol]: (channel, ctx) => void }`,
 *   served to the bridged operator in virtual data mode (the CBOR sequence rides `SessionData`, inside `EncryptedFrame` when the
 *   bridge is sealed), advertised as `rpc-virtual`, `rpc-protocol:<name>` and `rpc-max-message:<n>` in `ReverseAccept.features`
 *   (so it needs `reportFeatures`, the default). `@johnhenry/wsh/server`'s also takes the `wsh-host` and `wsh-fs` built-ins.
 * @param {number} [options.rpcMaxMessageBytes=1048576]
 * @param {number} [options.rpcMaxInflight=64]
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
 * @param {boolean} [options.requireOperatorProof=false] - wsh #117. Do not take the operator's identity from the relay.
 *   When the relay carries `operator-proof` (its ServerHello says so) and the operator can answer, this host sends it a
 *   signed challenge and verifies the operator's signature over this host's fingerprint, a nonce it chose and the
 *   bridge's session BEFORE `accept` runs; `accept` then receives `{ fingerprint, username, proven: true, publicKey }`
 *   taken from the proof, not from the relay (a relay that rewrote `from_fingerprint` is refused). This option makes
 *   that mandatory: an operator that does not prove itself is refused, and the bridge is SEALED -- this host acts only on
 *   messages the operator sealed under a key exchange both sides signed, because a relay can stamp any identity on a
 *   plain message (it could inject an `Open`). Needs `e2e` (on by default) and `reportFeatures`. Without this option the
 *   proof is requested when it can be and reported as `proven`, and the bridge is sealed only if the operator asks.
 * @param {number} [options.proofTimeoutMs=5000] - How long an operator has to answer the challenge.
 * @param {(name: string, fs: object, who: { username: string | null, fingerprint: string | null }) => void | Promise<void>} [options.onShare]
 *   Folders an operator offers (`ShareOffer`, #159), once per share, as an object of async file operations. The Rust CLI
 *   offers shares on a direct or pipe-relayed session (`wsh --share`), not over `wsh reverse-connect` yet.
 * @param {(refusal: { reason: string, who: { username?: string, fingerprint?: string, address?: string }, detail: string }) => void} [options.onRefused]
 *   #163: called when this host turns an operator away (`unauthorized` when `accept` says no, `busy`, `proof-required`,
 *   `proof-failed`, `not-sealed`, `seal-failed`; see `REFUSAL_REASONS`), with what is known of `who` and a human `detail`.
 * @param {(line: string) => void} [options.onLog]
 */
export function createReverseHost(options = {}) {
  // A gateway here dials only a network the embedder supplies (`gateway.network`): this entry has no sockets of its own (#299). Its shape is checked
  // now (a typo throws at once); the session behind it is fetched by a dynamic import only when a gateway was given, so a bundler splits it into a
  // chunk of its own, and the full validation runs then: `start()` rejects with the reason, nothing is dialled.
  let gateway = null;
  if (options.gateway !== undefined && options.gateway !== null && options.gateway !== false) {
    checkGatewayShape(options.gateway, 'createReverseHost', ['trustRelayIdentity']);
    checkReverseTrust(options.gateway, options, 'createReverseHost');
    gateway = { cfg: null, createGatewaySession: null, ready: null };
    gateway.ready = import('./reverse-gateway.mjs').then((m) => {
      const built = m.buildReverseGateway(options.gateway, options, { requireNetwork: true });
      gateway.cfg = built.cfg;
      gateway.createGatewaySession = built.createGatewaySession;
    });
    gateway.ready.catch(() => {});
  }
  const rpc = options.rpc === undefined || options.rpc === null ? null
    : createRpcTable(options.rpc, options.rpcMaxMessageBytes ?? RPC_DEFAULT_MAX_MESSAGE, options.rpcMaxInflight ?? 64, 'createReverseHost');
  return createReverseHostWith(options, { ...resolveBackends(options), rpc, gateway });
}

/**
 * The reverse host proper, given its backends already built: `createReverseHost` here builds them from injected
 * parts only (browser-safe); `@johnhenry/wsh/server`'s builds them with `exec: true` and `fs: { root }` as well.
 * @param {object} options - as for `createReverseHost` (its `exec`, `pty`, `fs` and `mcp` are read by the caller, not here)
 * @param {ReturnType<typeof resolveBackends>} backends
 */
export function createReverseHostWith({
  url, username, keyPair, accept, reconnect = true, connect = {}, peerType = 'host', reportFeatures = true, maxOperators = 1, e2e = {},
  requireOperatorProof = false, proofTimeoutMs = 5000, onLog = () => {}, onShare, onRefused,
} = {}, backends) {
  validateOnShare(onShare, 'createReverseHost');
  validateOnRefused(onRefused, 'createReverseHost');
  const notifyRefused = refusalNotifier(onRefused, onLog);
  if (typeof requireOperatorProof !== 'boolean') throw new TypeError('createReverseHost: requireOperatorProof must be a boolean');
  if (requireOperatorProof && e2e === false) throw new TypeError('createReverseHost: requireOperatorProof seals the bridge, which needs e2e (do not set e2e: false)');
  if (requireOperatorProof && !reportFeatures) throw new TypeError('createReverseHost: requireOperatorProof needs reportFeatures (the operator learns "e2e-sealed" from ReverseAccept.features)');
  if (backends.targets) throw new TypeError('createReverseHost: targets are not supported by a reverse host (a bridged operator reaches the one machine behind it); use createWshServer or createMemoryHost');
  if (backends.rpc?.protocols.size && !reportFeatures) throw new TypeError('createReverseHost: rpc needs reportFeatures (the operator learns "rpc-virtual" and the protocols from ReverseAccept.features)');
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

  if (backends.gateway && !reportFeatures) throw new TypeError('createReverseHost: gateway needs reportFeatures (the operator learns "relay-gateway" and the gateway features from ReverseAccept.features)');
  const expose = { shell: !!backends.pty, exec: !!backends.execRunner, fs: !!backends.files, tools: !!backends.mcp, gateway: !!backends.gateway };
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
  // The gateway (#289) is served, and stated, only on a relay that lists `relay-gateway`: any other would answer the requests itself.
  const gatewayOn = (c) => !!backends.gateway && c.hasFeature(RELAY_GATEWAY_FEATURE);
  const bridgeFeatures = (c, e2eConfig, manyOperators) => [
    ...hostFeatures({ mcp: backends.mcp, files: backends.files, e2e: e2eConfig, onShare, rpc: backends.rpc ?? null, gateway: gatewayOn(c) ? backends.gateway.cfg : null }, { dataStreams: false }),
    ...(gatewayOn(c) ? [RELAY_GATEWAY_FEATURE] : []),
    ...(manyOperators ? [MULTI_OPERATOR_FEATURE] : []),
  ];
  // Built on first use (`start()` has waited for a lazily loaded gateway by then).
  let factory = null;
  const makeFactory = () => createConnectionFactory({
    authorize: async () => false, methods: { pubkey: false, password: null }, hostKey: null, rateLimit: null,
    execRunner: backends.execRunner, execOptions: backends.execOptions, pty: backends.pty, files: backends.files, mcp: backends.mcp, rpc: backends.rpc ?? null,
    sessions: null, relay: null, e2e: null, bindTimeoutMs: 3000, log: (l) => onLog(`[reverse] ${l}`), onShare, onRefused,
    // #289: the gateway is the host's own policy (`gateway`); an operator uses it only with a granted capability, every connection is metered.
    gateway: backends.gateway?.cfg ?? null, createGatewaySession: backends.gateway?.createGatewaySession, gatewayNeedsGrant: true, gatewayCredit: true,
  });

  let client = null;
  /** The live connection's bridges (operator fingerprint -> connection), for `operators`. */
  let operatorsNow = new Map();
  /** Ends every bridge of the live connection (the client's own `disconnect()` does not call its `onClose`). */
  let endAllBridges = () => {};
  let myFingerprint = null;
  let myPublicKeyRaw = null;
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
    /** challenge nonce (hex) -> resolves with the operator's ReverseProof (or null on timeout) */
    const proofWaiters = new Map();
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
      const refuse = (reason, code = 'busy') => {
        notifyRefused(code, { fingerprint: typeof from === 'string' ? from : undefined, username: req.username }, reason);
        return answer(reverseReject({ targetFingerprint: myFingerprint, username, reason }));
      };
      if (typeof from !== 'string' || !from) { await refuse('busy: this host is already serving an operator', 'bad-request'); return; }
      if (bridges.has(from) || reserved.has(from)) { await refuse('busy: you already have a bridge with this host'); return; }
      if (bridges.size + reserved.size >= operatorLimit()) {
        await refuse(manyOperators() ? `busy: this host is already serving its maximum of ${maxOperators} operators` : 'busy: this host is already serving an operator');
        return;
      }
      reserved.add(from);
      let ok = false;
      try {
        // Who is this operator? The relay says (`from`); with proof the operator says so itself (#117).
        const canProve = c.hasFeature(OPERATOR_PROOF_FEATURE) && Array.isArray(req.features) && req.features.includes(OPERATOR_PROOF_FEATURE);
        if (requireOperatorProof && !canProve) { await refuse('operator proof required', 'proof-required'); return; }
        let proven = null;
        let challenge = null;
        if (canProve) {
          const outcome = await challengeOperator(c, from);
          if (outcome.error) { await refuse(outcome.error, 'proof-failed'); return; }
          ({ proven, challenge } = outcome);
          // The relay's claim and the operator's own must agree: a relay that rewrote from_fingerprint is caught here.
          if (proven.fingerprint !== from) { onLog(`[reverse] proof is by ${proven.fingerprint.slice(0, 12)}, the relay said ${from.slice(0, 12)}`); await refuse('operator proof does not match the identity the relay asserted', 'proof-failed'); return; }
          if (proven.username !== String(req.username ?? '')) { await refuse('operator proof names another username than the relay asserted', 'proof-failed'); return; }
        }
        const who = { fingerprint: from, username: String(req.username ?? ''), proven: !!proven, ...(proven ? { publicKey: proven.publicKey } : {}) };
        // `true`, or `{ capabilities, expires? }` (#289: the same grant `authorize()` may return; it narrows what this operator may do, and
        // is what lets it use the gateway). Anything else is a refusal.
        let grant = null;
        try {
          const verdict = await accept?.(who);
          if (verdict === true) ok = true;
          else if (verdict && typeof verdict === 'object' && !Array.isArray(verdict) && verdict.capabilities !== undefined) {
            // A grant NAMES what the operator may do: an object without `capabilities` is no grant (it would otherwise mean "everything"), so it refuses, as an object always did.
            const g = grantPermissions({ capabilities: verdict.capabilities, ...(verdict.expires !== undefined ? { expires: verdict.expires } : {}) });
            if (g.ok) { ok = true; grant = g.permissions; } else onLog(`[reverse] accept returned a grant that does not parse: ${g.reason}`);
          }
        } catch (e) { onLog(`[reverse] accept threw: ${e.message}`); }
        if (!ok) { await refuse('not accepted', 'unauthorized'); return; }
        if (bridges.size >= operatorLimit()) { await refuse('not accepted'); return; }
        c.trustRelayPeer(from);
        // #318: what the operator stated about the lossless close. Behind a proof it is what the operator SIGNED (a relay can add or strip the
        // unsigned list, and an operator that does not sign - a 0.62.x one - is not believed); with no proof there is nothing to check it against
        // and the relay's list is taken as before (the relay is trusted for identity on such a bridge).
        const reqFeatures = Array.isArray(req.features) ? req.features : [];
        const operatorFeatures = proven
          ? [...reqFeatures.filter((f) => f !== GATEWAY_LOSSLESS_FEATURE), ...(proven.signedFeatures ?? []).filter((f) => f === GATEWAY_LOSSLESS_FEATURE)]
          : reqFeatures;
        const bridge = makeBridge(c, from, String(req.username ?? 'operator'), proven, challenge, grant, operatorFeatures);
        bridges.set(from, bridge);
        onLog(`[reverse] bridged to ${from.slice(0, 12)}${proven ? ' (operator proven)' : ''}${requireOperatorProof ? ', sealed' : ''}`);
        await answer(reverseAccept({
          targetFingerprint: myFingerprint, username, capabilities, peerType, shellBackend,
          supportsAttach: false, supportsReplay: false, supportsEcho: false, supportsTermSync: false,
          // `gateway-lossless-close-ack` (#286): only when the operator's own statement reached this host (the relay may drop it)
          features: reportFeatures ? [...bridgeFeatures(c, e2eFor(c), manyOperators()), ...(proven && e2e !== false ? [E2E_SEALED_FEATURE] : []), ...(gatewayOn(c) && backends.gateway.cfg?.losslessClose !== false && operatorFeatures.includes(GATEWAY_LOSSLESS_FEATURE) ? [GATEWAY_LOSSLESS_ACK_FEATURE] : [])] : undefined,
        }));
      } finally { reserved.delete(from); }
    };

    /** Send a signed challenge, wait for the operator's proof and verify it. @returns {Promise<{ error?: string, proven?: object, challenge?: object }>} */
    async function challengeOperator(conn, from) {
      const issued = await createReverseChallenge({ keyPair }, from);
      const key = Array.from(issued.nonce, (b) => b.toString(16).padStart(2, '0')).join('');
      const proofMsg = new Promise((resolve) => { proofWaiters.set(key, resolve); });
      const timer = setTimeout(() => { proofWaiters.get(key)?.(null); }, proofTimeoutMs);
      timer.unref?.();
      try {
        await conn.sendRelayControl(reverseChallenge({ targetFingerprint: from, ...issued.fields }));
        const msg = await proofMsg;
        if (!msg) return { error: 'operator did not answer the challenge' };
        const proven = await verifyOperatorProof(msg, issued);
        if (!proven) return { error: 'operator proof does not verify' };
        return { proven, challenge: issued };
      } catch (e) {
        onLog(`[reverse] challenge failed: ${e.message}`);
        return { error: 'operator proof failed' };
      } finally { clearTimeout(timer); proofWaiters.delete(key); }
    }
    c.onReverseProof = (m) => {
      if (!(m.nonce instanceof Uint8Array)) return;
      const key = Array.from(m.nonce, (b) => b.toString(16).padStart(2, '0')).join('');
      proofWaiters.get(key)?.(m);
    };

    /**
     * The connection for one bridged operator. A proven operator may seal the bridge (a signed `KeyExchange` for the
     * challenge's session id); with `requireOperatorProof` it must, and until it has the host hears nothing else.
     */
    function makeBridge(conn, from, operatorName, proven, challenge, grant = null, operatorFeatures = []) {
      const to = () => (manyOperators() ? { to: from } : undefined);
      let sealed = null;
      const mustSeal = requireOperatorProof;
      const base = (factory ??= makeFactory())({
        // With several operators every message names its recipient; with one the relay knows.
        sendMessage: async (m) => {
          if (sealed) return conn.sendRelayControl(await sealed.seal(m), to());
          if (mustSeal) return undefined; // nothing may leave a bridge that is not sealed yet
          return conn.sendRelayControl(m, to());
        },
        // `features`: what the operator stated in ReverseConnect (gateway-lossless-close, #286), as the relay passed it on.
        authenticated: { username: operatorName, fingerprint: from, grant, features: operatorFeatures },
        dataStreams: false,
        e2e: e2eFor(conn),
      });
      if (!proven || e2e === false) return base;

      const responder = new E2EResponder({
        signKey: keyPair.privateKey, hybrid: e2e.hybrid !== false, identity: myPublicKeyRaw,
        initiator: { publicKey: proven.publicKey, require: true },
      });
      let chain = Promise.resolve();
      let giveUp = null;
      const who = { fingerprint: from, username: operatorName };
      let unsealedReported = false;
      // #162: the operator sends its first frame the moment ITS half of the exchange is done, which can be before this
      // host has derived its own key (it still decapsulates and combines after the ciphertext arrives). Bridge-level
      // frames of this bridge's session that arrive in that window are held (bounded), not dropped as "not sealed".
      let exchanging = false;
      const early = [];
      const MAX_EARLY_FRAMES = 16;
      const openSealed = (frame) => {
        // A frame that does not open (altered, replayed, reordered, or not from this bridge's key) means whoever carries the bridge is not
        // honest, or it is broken: nothing more is heard over it (a gap would otherwise leave a connection that never ends).
        chain = chain.then(async () => base.receiveMessage(await sealed.open(frame))).catch((e) => fail(`a sealed frame did not open (${e.message})`));
      };
      const fail = (why) => { early.length = 0; onLog(`[reverse] sealed bridge with ${from.slice(0, 12)} failed: ${why}`); notifyRefused('seal-failed', who, why); endBridge(from); };
      if (mustSeal) {
        giveUp = setTimeout(() => { if (!sealed) fail('no key exchange in time'); }, proofTimeoutMs * 2);
        giveUp.unref?.();
      }
      return {
        receiveMessage(msg) {
          if (sealed) {
            if (!sealed.isFrame(msg)) { onLog('[reverse] dropped a plaintext message on a sealed bridge'); return; }
            openSealed(msg);
            return;
          }
          if (msg.type === MSG.KEY_EXCHANGE && msg.session_id === challenge.sessionId) {
            exchanging = true;
            chain = chain.then(async () => {
              const result = await responder.respond(msg, (reply) => conn.sendRelayControl(reply, to()));
              if (result.key) {
                sealed = new SealedBridge({ key: result.key, sessionId: challenge.sessionId, role: 'responder' });
                clearTimeout(giveUp);
                onLog(`[reverse] bridge to ${from.slice(0, 12)} sealed${result.hybrid ? ' (hybrid)' : ''}`);
                for (const frame of early.splice(0)) openSealed(frame);
              }
            }).catch((e) => fail(e.message));
            return;
          }
          if (exchanging && msg.type === MSG.ENCRYPTED_FRAME && msg.channel_id === BRIDGE_CHANNEL_ID && msg.session_id === challenge.sessionId) {
            if (early.length < MAX_EARLY_FRAMES) early.push(msg);
            else onLog('[reverse] dropped a sealed frame: too many arrived before the key exchange finished');
            return;
          }
          if (mustSeal) {
            onLog(`[reverse] dropped a message that is not sealed (type ${msg.type}) on a bridge that must be`);
            if (!unsealedReported) { unsealedReported = true; notifyRefused('not-sealed', who, `a message that is not sealed (type ${msg.type}) on a bridge that must be`); }
            return;
          }
          base.receiveMessage(msg);
        },
        bindStream: (s) => base.bindStream?.(s),
        close() { clearTimeout(giveUp); responder.close(); base.close(); },
      };
    }
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
      // #318: this host reads an operator's SIGNED `gateway-lossless-close` (an operator signs it only for a host whose record says so)
      gatewayLosslessSigned: backends.gateway?.cfg?.losslessClose !== false,
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
      await backends.gateway?.ready; // a gateway loaded on demand (#299): an invalid one rejects here, before anything is dialled
      myPublicKeyRaw = await exportPublicKeyRaw(keyPair.publicKey);
      myFingerprint = await fingerprint(myPublicKeyRaw);
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
