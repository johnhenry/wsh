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
 * types cross a bridge. One bridge per peer at a time, and it lasts as long as
 * both connections: when either ends the hub closes the other, so no
 * half-bridged state (and no processes belonging to a departed operator)
 * outlives it.
 */

import { cborEncode, cborDecode } from '../cbor.mjs';
import { fingerprint as fingerprintOf, importPublicKeyRaw, verifyPeerRecord } from '../auth.mjs';
import { MSG, isRelayForwardable, relayForward, reversePeers, reverseReject } from '../messages.gen.mjs';

export const DEFAULT_MAX_PEERS = 1024;
export const DEFAULT_CONNECT_TIMEOUT_MS = 8000;
const MAX_FORWARD_BYTES = 8 * 1024 * 1024;
const MAX_REMEMBERED_SEQS = 4096;
const MAX_CAPABILITIES = 32;
const MAX_FEATURES = 64;
const MAX_FEATURE_LENGTH = 128;
const SHORT_PREFIX_MIN = 8;

/** `ReverseReject.reason` for a peer that already has an operator (or a request awaiting its answer). */
export const BUSY_PEER = 'busy: this peer already has an operator (the relay bridges one operator per peer at a time; retry when it leaves)';
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
  /** @type {Map<RelayHandle, RelayHandle>} */
  #pairs = new Map();
  /** target handle -> { operator, timer } while a ReverseConnect awaits its answer */
  #pending = new Map();
  /** fingerprint -> the highest record seq ever accepted (survives disconnects, bounded). */
  #lastSeq = new Map();

  constructor({ canRegister, canConnect, maxPeers = DEFAULT_MAX_PEERS, connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS, log = () => {} } = {}) {
    for (const [name, fn] of [['canRegister', canRegister], ['canConnect', canConnect]]) {
      if (fn !== undefined && typeof fn !== 'function') throw new TypeError(`createWshServer: relay.${name} must be a function`);
    }
    this.canRegister = canRegister ?? (() => false);
    this.canConnect = canConnect ?? (() => false);
    this.maxPeers = maxPeers;
    this.connectTimeoutMs = connectTimeoutMs;
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
    // Unknown, unreachable-by-policy and self look the same to the caller.
    if (!target || target.handle === operator
      || !(await this.#allowed(this.canConnect, { username: operator.username, fingerprint: operator.fingerprint }, {
        fingerprint: target.meta.fingerprint, username: target.meta.username, capabilities: target.meta.capabilities,
      }))) return reject('no such peer');
    if (this.#peers.get(target.meta.fingerprint) !== target) return reject('no such peer');
    // One bridge per peer, and one per operator: a RelayForward names its sender but not its recipient, so a
    // peer's reply could not be addressed to one of several operators (see the README's relay section).
    if (this.#pairs.has(target.handle) || this.#pending.has(target.handle)) {
      return reject(BUSY_PEER);
    }
    if (this.#pairs.has(operator) || [...this.#pending.values()].some((p) => p.operator === operator)) {
      return reject(BUSY_OPERATOR);
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
      this.#pairs.set(p.operator, peer);
      this.#pairs.set(peer, p.operator);
      this.log(`relay: bridged ${p.operator.fingerprint.slice(0, 12)} <-> ${peer.fingerprint.slice(0, 12)}`);
    }
  }

  /** Is `handle` one end of a bridge? */
  bridged(handle) {
    return this.#pairs.has(handle);
  }

  /**
   * Carry a message across `handle`'s bridge. A plain forwardable message is
   * wrapped; a `RelayForward` the client wrote itself is unwrapped, its inner
   * checked, and re-wrapped -- either way `from_fingerprint` is the sender's
   * authenticated key. Returns false when there is no bridge.
   */
  forward(handle, msg) {
    const partner = this.#pairs.get(handle);
    if (!partner) return false;
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

  /** A connection ended: forget it, and end the bridge it was part of. */
  drop(handle) {
    const entry = this.#peers.get(handle.fingerprint);
    if (entry && entry.handle === handle) this.#peers.delete(handle.fingerprint);
    const p = this.#pending.get(handle);
    if (p) { clearTimeout(p.timer); this.#pending.delete(handle); p.operator.send(reverseReject({ targetFingerprint: handle.fingerprint, username: '', reason: 'peer went away' })); }
    for (const [target, pend] of this.#pending) {
      if (pend.operator === handle) { clearTimeout(pend.timer); this.#pending.delete(target); }
    }
    const partner = this.#pairs.get(handle);
    if (partner) {
      this.#pairs.delete(handle);
      this.#pairs.delete(partner);
      partner.close();
    }
  }

  /** Server shutdown. */
  closeAll() {
    for (const p of this.#pending.values()) clearTimeout(p.timer);
    this.#pending.clear();
    this.#pairs.clear();
    this.#peers.clear();
  }
}
