/**
 * Relay (reverse-mode) hub for `@johnhenry/wsh/server`: what lets a host that
 * cannot accept connections (behind NAT, or a browser tab) register with this
 * server, and an operator reach it through it.
 *
 *   peer      --ReverseRegister-->  hub   (a signed peer record, verified here)
 *   operator  --ReverseList----->   hub   (peers it may connect to)
 *   operator  --ReverseConnect-->   hub  --ReverseConnect(from_fingerprint)--> peer
 *   peer      --ReverseAccept---->  hub  --ReverseAccept------------------>  operator
 *   operator <==RelayForward{from_fingerprint, inner}==> peer     (bridged)
 *
 * Nothing is open by default: `canRegister` and `canConnect` both default to
 * "no". `from_fingerprint` is always the sender's own authenticated key, set
 * here and never taken from a payload; only the spec's `forwardable` message
 * types cross a bridge.
 *
 * By default there is one operator per peer, and the bridge lasts as long as
 * both connections: when either ends the hub closes the other, so no
 * half-bridged state (and no processes belonging to a departed operator)
 * outlives it. With `maxOperatorsPerPeer` > 1 a peer that states
 * `relay-multi-operator` in its ReverseAccept may be bridged to several
 * operators at once (#89): it addresses each reply with
 * `RelayForward.to_fingerprint`, and is told with a `ReverseClose` when one
 * operator leaves (instead of being closed). A peer that never stated it is
 * still held to one operator, and still closed when its operator leaves.
 */

import { cborEncode, cborDecode } from '../cbor.mjs';
import { fingerprint as fingerprintOf, importPublicKeyRaw, verifyPeerRecord } from '../auth.mjs';
import { MSG, isRelayForwardable, relayForward, reversePeers, reverseReject, reverseClose } from '../messages.gen.mjs';

export const DEFAULT_MAX_PEERS = 1024;
export const DEFAULT_CONNECT_TIMEOUT_MS = 8000;
const MAX_FORWARD_BYTES = 8 * 1024 * 1024;
const MAX_REMEMBERED_SEQS = 4096;
const MAX_CAPABILITIES = 32;
const MAX_FEATURES = 64;
const MAX_FEATURE_LENGTH = 128;
const SHORT_PREFIX_MIN = 8;

/** `ReverseReject.reason` for a peer that already has an operator (or a request awaiting its answer). */
/** `ReverseAccept.features` entry by which a peer says it serves several operators (addresses replies, understands `ReverseClose`). */
export const MULTI_OPERATOR_FEATURE = 'relay-multi-operator';
/** `ReverseReject.reason` for a peer that is answering another operator's request right now. */
export const BUSY_ANSWERING = 'busy: this peer is answering another operator\'s request (retry in a moment)';

export const BUSY_PEER = 'busy: this peer already has an operator (the relay bridges one operator per peer at a time; retry when it leaves)';
/** `ReverseReject.reason` for a multi-operator peer already at the relay's operator cap. */
export function busyPeerFull(max) {
  return `busy: this peer already has its maximum of ${max} operators (retry when one leaves)`;
}
/** `ReverseReject.reason` for an operator that already has a bridge, or a request in flight. */
export const BUSY_OPERATOR = 'busy: you already have a bridge or a pending connect on this relay (one at a time)';

const isStr = (v, max) => typeof v === 'string' && v.length <= max;

/**
 * A connection as the hub sees it.
 * @typedef {object} RelayHandle
 * @property {(msg: object) => unknown} send - deliver a message to that connection
 * @property {() => void} close - end that connection
 * @property {string} fingerprint - its authenticated key
 * @property {string} username
 */

export class RelayHub {
  /** @type {Map<string, { handle: RelayHandle, meta: object }>} */
  #peers = new Map();
  /** operator -> the peer it is bridged to (an operator has one bridge). @type {Map<RelayHandle, RelayHandle>} */
  #operatorPeer = new Map();
  /** peer -> its bridged operators, by the operator's fingerprint. @type {Map<RelayHandle, Map<string, RelayHandle>>} */
  #peerOperators = new Map();
  /** peers that stated `relay-multi-operator` in their last ReverseAccept. @type {WeakSet<RelayHandle>} */
  #multiPeers = new WeakSet();
  /** target handle -> { operator, timer } while a ReverseConnect awaits its answer */
  #pending = new Map();
  /** fingerprint -> the highest record seq ever accepted (survives disconnects, bounded). */
  #lastSeq = new Map();

  constructor({ canRegister, canConnect, maxPeers = DEFAULT_MAX_PEERS, maxOperatorsPerPeer = 1, connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS, onUnreachable, log = () => {} } = {}) {
    for (const [name, fn] of [['canRegister', canRegister], ['canConnect', canConnect], ['onUnreachable', onUnreachable]]) {
      if (fn !== undefined && typeof fn !== 'function') throw new TypeError(`createWshServer: relay.${name} must be a function`);
    }
    if (!Number.isSafeInteger(maxOperatorsPerPeer) || maxOperatorsPerPeer < 1) throw new TypeError('createWshServer: relay.maxOperatorsPerPeer must be a positive integer');
    this.maxOperatorsPerPeer = maxOperatorsPerPeer;
    this.canRegister = canRegister ?? (() => false);
    this.canConnect = canConnect ?? (() => false);
    this.maxPeers = maxPeers;
    this.connectTimeoutMs = connectTimeoutMs;
    this.onUnreachable = onUnreachable;
    this.log = log;
  }

  get peerCount() { return this.#peers.size; }

  /** Fingerprints currently registered. */
  peerFingerprints() { return [...this.#peers.keys()]; }

  async #allowed(fn, ...args) {
    try { return (await fn(...args)) === true; } catch (e) { this.log(`relay policy threw: ${e.message}`); return false; }
  }

  /**
   * Verify and record a `ReverseRegister`. Resolves to `null` on success or a reason.
   * @param {RelayHandle} handle
   * @param {object} msg
   * @param {{ username: string, fingerprint: string }} who - the authenticated connection
   */
  async register(handle, msg, who) {
    // Cheap structural checks first, then policy, then the signature (the expensive part).
    if (!(msg.public_key instanceof Uint8Array) || !(msg.record_signature instanceof Uint8Array)) return 'missing signed-record fields';
    const seq = typeof msg.seq === 'bigint' ? Number(msg.seq) : msg.seq;
    if (!Number.isSafeInteger(seq) || seq < 0) return 'missing or invalid record seq';
    if (!isStr(msg.username, 64) || !isStr(msg.peer_type ?? 'host', 64) || !isStr(msg.shell_backend ?? 'pty', 64)) return 'malformed record';
    const caps = msg.capabilities ?? [];
    if (!Array.isArray(caps) || caps.length > MAX_CAPABILITIES || !caps.every((c) => isStr(c, 64))) return 'malformed capabilities';
    if ((await fingerprintOf(msg.public_key)) !== who.fingerprint) return 'public_key does not match the authenticated identity';

    if (!(await this.#allowed(this.canRegister, { username: who.username, fingerprint: who.fingerprint }, {
      username: msg.username, capabilities: caps, peerType: msg.peer_type ?? 'host', shellBackend: msg.shell_backend ?? 'pty',
    }))) return 'registration not permitted';

    const previous = this.#lastSeq.get(who.fingerprint);
    if (previous !== undefined && seq <= previous) return `stale record (seq ${seq} <= ${previous})`;

    let key;
    try { key = await importPublicKeyRaw(msg.public_key); } catch { return 'malformed public_key'; }
    let ok = false;
    try {
      ok = await verifyPeerRecord(key, msg.record_signature, {
        username: msg.username,
        peerType: msg.peer_type,
        shellBackend: msg.shell_backend,
        capabilities: msg.capabilities,
        supportsAttach: msg.supports_attach,
        supportsReplay: msg.supports_replay,
        supportsEcho: msg.supports_echo,
        supportsTermSync: msg.supports_term_sync,
        seq,
      });
    } catch { ok = false; }
    if (!ok) return 'record signature does not verify';

    // Re-check after the awaits: a concurrent registration may have moved the counter.
    const latest = this.#lastSeq.get(who.fingerprint);
    if (latest !== undefined && seq <= latest) return `stale record (seq ${seq} <= ${latest})`;
    const existing = this.#peers.get(who.fingerprint);
    if (!existing && this.#peers.size >= this.maxPeers) return 'relay is full';

    this.#lastSeq.delete(who.fingerprint);
    this.#lastSeq.set(who.fingerprint, seq);
    while (this.#lastSeq.size > MAX_REMEMBERED_SEQS) this.#lastSeq.delete(this.#lastSeq.keys().next().value);

    if (existing && existing.handle !== handle) {
      // The same key came back on a new connection: the old one is dead or superseded.
      this.#peers.delete(who.fingerprint);
      this.drop(existing.handle);
      existing.handle.close();
    }
    this.#peers.set(who.fingerprint, {
      handle,
      meta: {
        fingerprint: who.fingerprint,
        fingerprint_short: who.fingerprint.slice(0, 12),
        username: msg.username,
        capabilities: [...caps],
        peer_type: msg.peer_type ?? 'host',
        shell_backend: msg.shell_backend ?? 'pty',
        source: 'wsh-relay',
        supports_attach: !!msg.supports_attach,
        supports_replay: !!msg.supports_replay,
        supports_echo: !!msg.supports_echo,
        supports_term_sync: !!msg.supports_term_sync,
        last_seen: Date.now(),
        public_key: msg.public_key,
        seq,
        record_signature: msg.record_signature,
      },
    });
    this.log(`relay: peer registered ${who.fingerprint.slice(0, 12)} (${msg.username})`);
    return null;
  }

  /** Is this connection a registered peer? Refreshes its `last_seen` when it is. */
  touch(handle) {
    const e = this.#peers.get(handle.fingerprint);
    if (e && e.handle === handle) e.meta.last_seen = Date.now();
  }

  /** The peers `who` is allowed to connect to -- an operator sees only what it could reach. */
  async list(who) {
    const out = [];
    for (const { meta, handle } of this.#peers.values()) {
      if (handle.fingerprint === who.fingerprint) continue;
      if (await this.#allowed(this.canConnect, who, { fingerprint: meta.fingerprint, username: meta.username, capabilities: meta.capabilities })) out.push({ ...meta });
    }
    return reversePeers({ peers: out });
  }

  #find(target) {
    if (typeof target !== 'string') return undefined;
    const exact = this.#peers.get(target);
    if (exact) return exact;
    if (target.length < SHORT_PREFIX_MIN) return undefined;
    const hits = [...this.#peers.values()].filter((p) => p.meta.fingerprint.startsWith(target));
    return hits.length === 1 ? hits[0] : undefined;
  }

  /** `ReverseConnect` from `operator`: forward it to the target, with the identity the hub knows. */
  async connect(operator, msg) {
    const reject = (reason) => operator.send(reverseReject({ targetFingerprint: String(msg.target_fingerprint ?? ''), username: msg.username ?? '', reason }));
    const target = this.#find(msg.target_fingerprint);
    if (!target && this.onUnreachable) {
      // Tell the host application nobody is registered under that name (it may know another way to reach them, e.g. a
      // push notification). Fire and forget: it never changes the answer, and a throw is logged, not propagated.
      try {
        Promise.resolve(this.onUnreachable({ username: operator.username, fingerprint: operator.fingerprint }, String(msg.target_fingerprint ?? ''), { username: msg.username }))
          .catch((e) => this.log(`relay onUnreachable threw: ${e.message}`));
      } catch (e) { this.log(`relay onUnreachable threw: ${e.message}`); }
    }
    // Unknown, unreachable-by-policy and self look the same to the caller.
    if (!target || target.handle === operator
      || !(await this.#allowed(this.canConnect, { username: operator.username, fingerprint: operator.fingerprint }, {
        fingerprint: target.meta.fingerprint, username: target.meta.username, capabilities: target.meta.capabilities,
      }))) return reject('no such peer');
    if (this.#peers.get(target.meta.fingerprint) !== target) return reject('no such peer');
    // One bridge per operator. A peer serves one operator unless the relay allows more AND the peer said it can
    // address them (RelayForward.to_fingerprint) and be told when one leaves (ReverseClose); it also answers one
    // request at a time, since a ReverseAccept does not name the operator it answers.
    if (this.bridged(operator) || [...this.#pending.values()].some((p) => p.operator === operator)) {
      return reject(BUSY_OPERATOR);
    }
    if (this.#pending.has(target.handle)) return reject(this.maxOperatorsPerPeer > 1 ? BUSY_ANSWERING : BUSY_PEER);
    const serving = this.#peerOperators.get(target.handle);
    if (serving?.size) {
      if (this.maxOperatorsPerPeer < 2 || !this.#multiPeers.has(target.handle)) return reject(BUSY_PEER);
      if (serving.has(operator.fingerprint)) return reject(BUSY_OPERATOR);
      if (serving.size >= this.maxOperatorsPerPeer) return reject(busyPeerFull(this.maxOperatorsPerPeer));
    }
    const timer = setTimeout(() => {
      if (this.#pending.get(target.handle)?.operator !== operator) return;
      this.#pending.delete(target.handle);
      reject('peer did not respond');
    }, this.connectTimeoutMs);
    timer.unref?.();
    this.#pending.set(target.handle, { operator, timer });
    // The relay speaks for the operator's identity; whatever the client wrote in these fields is discarded.
    target.handle.send({
      type: MSG.REVERSE_CONNECT,
      target_fingerprint: target.meta.fingerprint,
      username: operator.username,
      from_fingerprint: operator.fingerprint,
    });
    this.log(`relay: ${operator.fingerprint.slice(0, 12)} -> ${target.meta.fingerprint.slice(0, 12)} requested`);
  }

  /** `ReverseAccept` / `ReverseReject` from a peer, answering a pending `connect`. */
  answer(peer, msg) {
    const p = this.#pending.get(peer);
    if (!p) return;
    clearTimeout(p.timer);
    this.#pending.delete(peer);
    // The answer names the answering peer, not whatever it wrote; its features claim is bounded.
    const answer = { ...msg, target_fingerprint: peer.fingerprint };
    if (msg.type === MSG.REVERSE_ACCEPT) {
      if (Array.isArray(msg.features) && msg.features.length <= MAX_FEATURES && msg.features.every((f) => isStr(f, MAX_FEATURE_LENGTH))) answer.features = [...msg.features];
      else delete answer.features;
    }
    p.operator.send(answer);
    if (msg.type === MSG.REVERSE_ACCEPT) {
      if (Array.isArray(answer.features) && answer.features.includes(MULTI_OPERATOR_FEATURE)) this.#multiPeers.add(peer);
      else this.#multiPeers.delete(peer);
      this.#operatorPeer.set(p.operator, peer);
      let ops = this.#peerOperators.get(peer);
      if (!ops) this.#peerOperators.set(peer, ops = new Map());
      ops.set(p.operator.fingerprint, p.operator);
      this.log(`relay: bridged ${p.operator.fingerprint.slice(0, 12)} <-> ${peer.fingerprint.slice(0, 12)}`);
    }
  }

  /** Is `handle` one end of a bridge? */
  bridged(handle) {
    return this.#operatorPeer.has(handle) || (this.#peerOperators.get(handle)?.size ?? 0) > 0;
  }

  /** Fingerprints of the operators bridged to the peer with this fingerprint. */
  operatorsOf(peerFingerprint) {
    const peer = this.#peers.get(peerFingerprint)?.handle;
    return peer ? [...(this.#peerOperators.get(peer)?.keys() ?? [])] : [];
  }

  /**
   * Carry a message across `handle`'s bridge. A plain forwardable message is
   * wrapped; a `RelayForward` the client wrote itself is unwrapped, its inner
   * checked, and re-wrapped -- either way `from_fingerprint` is the sender's
   * authenticated key. A peer serving several operators names the recipient
   * with `to_fingerprint` (never set on what is delivered); with one operator
   * it may leave it out. Returns false when there is no bridge.
   */
  forward(handle, msg) {
    const partner = this.#recipient(handle, msg);
    if (partner === undefined) return false;
    if (partner === null) return true; // bridged, but the message could not be addressed: dropped (and logged)
    let inner;
    if (msg.type === MSG.RELAY_FORWARD) {
      if (!(msg.inner instanceof Uint8Array) || msg.inner.byteLength > MAX_FORWARD_BYTES) { this.log('relay: dropped an oversized or malformed RelayForward'); return true; }
      let decoded;
      try { decoded = cborDecode(msg.inner); } catch { this.log('relay: dropped a RelayForward with an undecodable inner'); return true; }
      if (!decoded || typeof decoded.type !== 'number' || !isRelayForwardable(decoded.type)) {
        this.log(`relay: dropped a RelayForward wrapping a non-forwardable type ${decoded?.type}`);
        return true;
      }
      inner = msg.inner;
    } else {
      if (!isRelayForwardable(msg.type)) return false;
      inner = cborEncode(msg);
    }
    partner.send(relayForward({ fromFingerprint: handle.fingerprint, inner }));
    return true;
  }

  /**
   * Who `msg` from `handle` goes to: the partner handle; `undefined` if `handle` has no bridge (the caller
   * treats the message as an ordinary one); `null` if it has one but the recipient cannot be determined.
   */
  #recipient(handle, msg) {
    const peer = this.#operatorPeer.get(handle);
    if (peer) return peer; // an operator has exactly one bridge
    const operators = this.#peerOperators.get(handle);
    if (!operators || operators.size === 0) return undefined;
    const to = msg.type === MSG.RELAY_FORWARD ? msg.to_fingerprint : undefined;
    if (to !== undefined) {
      const operator = typeof to === 'string' ? operators.get(to) : undefined;
      if (operator) return operator;
      this.log(`relay: dropped a forward from ${handle.fingerprint.slice(0, 12)} addressed to ${typeof to === 'string' ? to.slice(0, 12) : '?'}, which is not one of its operators`);
      return null;
    }
    if (operators.size === 1) return operators.values().next().value;
    this.log(`relay: dropped an unaddressed forward from ${handle.fingerprint.slice(0, 12)}, which serves ${operators.size} operators (to_fingerprint is required)`);
    return null;
  }

  /** A connection ended: forget it, and end the bridge it was part of. */
  drop(handle) {
    const entry = this.#peers.get(handle.fingerprint);
    if (entry && entry.handle === handle) this.#peers.delete(handle.fingerprint);
    const p = this.#pending.get(handle);
    if (p) { clearTimeout(p.timer); this.#pending.delete(handle); p.operator.send(reverseReject({ targetFingerprint: handle.fingerprint, username: '', reason: 'peer went away' })); }
    for (const [target, pend] of this.#pending) {
      if (pend.operator === handle) { clearTimeout(pend.timer); this.#pending.delete(target); }
    }
    // An operator leaving.
    const peer = this.#operatorPeer.get(handle);
    if (peer) {
      this.#operatorPeer.delete(handle);
      const operators = this.#peerOperators.get(peer);
      operators?.delete(handle.fingerprint);
      if (this.maxOperatorsPerPeer > 1 && this.#multiPeers.has(peer)) {
        // The peer serves others too (or may serve more): tell it which operator left instead of closing it.
        peer.send(reverseClose({ targetFingerprint: handle.fingerprint, reason: 'operator left' }));
      } else {
        this.#peerOperators.delete(peer);
        peer.close();
      }
    }
    // A peer leaving: every operator bridged to it goes with it.
    const operators = this.#peerOperators.get(handle);
    if (operators) {
      this.#peerOperators.delete(handle);
      for (const operator of operators.values()) {
        this.#operatorPeer.delete(operator);
        operator.close();
      }
    }
  }

  /** Server shutdown. */
  closeAll() {
    for (const p of this.#pending.values()) clearTimeout(p.timer);
    this.#pending.clear();
    this.#operatorPeer.clear();
    this.#peerOperators.clear();
    this.#peers.clear();
  }
}
