/**
 * A sealed bridge (wsh #117): everything two endpoints say to each other across a relay, sealed under a key they
 * agreed with a signed `KeyExchange` whose `session_id` is the bridge's, so the relay carries ciphertext it cannot
 * read, forge, replay or reorder -- and, because a relay can stamp any `from_fingerprint` on a PLAIN message, cannot
 * make a peer act for an operator that is not there.
 *
 * Each message that would cross the bridge is CBOR-encoded and sealed with the same AES-256-GCM framing as session
 * data (`e2e-frame.mjs`: a strict send counter, a role tag per direction, `session_id` as AAD) into an
 * `EncryptedFrame` with `channel_id` 0 (real channels start at 1). The receiver opens it and handles the inner
 * message as if it had arrived plain; a plain message on a sealed bridge is dropped.
 *
 * Browser-safe: Web Crypto and the CBOR codec only.
 */

import { sealFrame, openFrame, ROLE_TAGS } from './e2e-frame.mjs';
import { cborEncode, cborDecode } from './cbor.mjs';
import { encryptedFrame, MSG, isRelayForwardable, isRelayGatewayForwardable } from './messages.gen.mjs';

/** `EncryptedFrame.channel_id` of a bridge-level frame. */
export const BRIDGE_CHANNEL_ID = 0;

export class SealedBridge {
  #key;
  #scope;
  #sessionId;
  #sendTag;
  #recvTag;
  #sendCounter = 0;
  #recvCounter = 0;
  #outChain = Promise.resolve();
  #inChain = Promise.resolve();

  /**
   * @param {{ key: CryptoKey, sessionId: string, role: 'initiator' | 'responder', scope?: 'bridge' | 'session' }} p -
   *   `initiator` is the operator. `scope: 'session'` (#155) seals a whole direct or pipe-relayed connection, so any
   *   message may be inside a frame; the default, a bridge, accepts only what a relay may forward.
   */
  constructor({ key, sessionId, role, scope = 'bridge' }) {
    if (scope !== 'bridge' && scope !== 'session') throw new TypeError("SealedBridge: scope must be 'bridge' or 'session'");
    this.#scope = scope;
    if (role !== 'initiator' && role !== 'responder') throw new TypeError("SealedBridge: role must be 'initiator' or 'responder'");
    this.#key = key;
    this.#sessionId = sessionId;
    this.#sendTag = ROLE_TAGS[role];
    this.#recvTag = ROLE_TAGS[role === 'initiator' ? 'responder' : 'initiator'];
  }

  get sessionId() { return this.#sessionId; }

  /** Is `msg` a bridge-level frame of this bridge? */
  isFrame(msg) {
    return msg?.type === MSG.ENCRYPTED_FRAME && msg.channel_id === BRIDGE_CHANNEL_ID && msg.session_id === this.#sessionId;
  }

  /** Seal one message; calls are sealed (and so must be sent) in call order. @returns {Promise<object>} an `EncryptedFrame` */
  seal(msg) {
    const counter = this.#sendCounter++;
    const run = this.#outChain.then(async () => {
      const { nonce, ciphertext } = await sealFrame(this.#key, this.#sessionId, this.#sendTag, counter, cborEncode(msg));
      return encryptedFrame({ channelId: BRIDGE_CHANNEL_ID, nonce, ciphertext, sessionId: this.#sessionId });
    });
    this.#outChain = run.catch(() => {});
    return run;
  }

  /**
   * Open one frame. A replayed, reordered, forged or foreign frame throws and does not consume a counter.
   * @returns {Promise<object>} the inner message, which is always one a relay may forward
   */
  open(frame) {
    const run = this.#inChain.then(async () => {
      if (!this.isFrame(frame)) throw new Error('not a frame of this bridge');
      const plain = await openFrame(this.#key, this.#sessionId, this.#recvCounter, { nonce: frame.nonce, ciphertext: frame.ciphertext, expectedRoleTag: this.#recvTag });
      this.#recvCounter += 1;
      const inner = cborDecode(plain);
      // What a bridge carries: the relay forwardable list and, where `relay-gateway` is in force, the gateway's requests (#289).
      // Whether it IS in force is for the receiver to decide; a peer that did not state it has no handler for them.
      if (!inner || typeof inner.type !== 'number' || inner.type === MSG.RELAY_FORWARD || (this.#scope === 'bridge' && !isRelayForwardable(inner.type) && !isRelayGatewayForwardable(inner.type))) throw new Error('sealed message of a type that may not cross a bridge');
      return inner;
    });
    this.#inChain = run.catch(() => {});
    return run;
  }
}
