//! The gate every control message of a client passes when a bridge may be (or is) sealed
//! (wsh #117, #145): what leaves a sealed bridge is sealed, what arrives on one must be a frame
//! of it, and until the key exists a bridge that must be sealed carries nothing but the key
//! exchange -- nothing that names a command, a path or a session is sent, and nothing plain is
//! heard.
//!
//! Outgoing: a message a relay may forward is sealed into an `EncryptedFrame` on channel 0, in
//! the order the dispatch loop sends it (the frame counter is strict). The relay-level answers
//! (`ReverseAccept` / `ReverseReject`), the key exchange of the bridge's own session, and every
//! message a relay does not forward (`Ping`, `ReverseConnect`, `ReverseProof`, ...) stay plain.
//! Incoming: a plain message a relay may forward is dropped on a sealed bridge, whether or not
//! the relay wrapped it in a `RelayForward`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio::sync::Notify;
use wsh_core::codec::{decode_envelope, frame_encode};
use wsh_core::messages::{
    is_relay_forwardable, is_relay_gateway_forwardable, Envelope, MsgType, Payload,
};

use crate::bridge_seal::{Scope, SealedBridge};
use crate::e2e::E2eResponder;
use crate::e2e_frame::RoleTag;

/// Host feature (wsh #155): this host seals the whole session when asked.
pub const SESSION_SEAL_FEATURE: &str = "e2e-session";
/// Host feature: this host serves nothing on a session that is not sealed.
pub const SESSION_SEAL_REQUIRED_FEATURE: &str = "e2e-session-required";

enum Mode {
    Off,
    /// The key does not exist yet. `must`: nothing but the key exchange may cross meanwhile.
    /// `responder`: this side answers the peer's `KeyExchange` itself, here, so the key is in
    /// place before the next frame is read (the peer sends its first sealed frame at once).
    Pending {
        session_id: String,
        must: bool,
        scope: Scope,
        responder: Option<Box<E2eResponder>>,
    },
    Sealed(SealedBridge),
    /// A frame of the bridge did not open (forged, tampered with, replayed, reordered): the
    /// relay is not honest, so the bridge is over. Nothing crosses any more.
    Failed,
}

/// See the module documentation. `Default` is the gate that is off.
pub struct SealGate {
    mode: Mutex<Mode>,
    failed: Notify,
    sealed: Notify,
    /// The operator side: a failed bridge ends the connection (there is nothing left to talk to).
    close_on_failure: AtomicBool,
    /// A peer that serves several operators (wsh #93) must know WHICH operator a forwarded message
    /// came from: with this on, a forwarded message that goes to the relay-message channel stays
    /// wrapped in the `RelayForward` the relay sent (its `from_fingerprint` is the sender).
    tag_relay_origin: AtomicBool,
}

impl Default for SealGate {
    fn default() -> Self {
        Self {
            mode: Mutex::new(Mode::Off),
            failed: Notify::new(),
            sealed: Notify::new(),
            close_on_failure: AtomicBool::new(false),
            tag_relay_origin: AtomicBool::new(false),
        }
    }
}

/// What the gate decided about a forwarded message.
#[derive(Default)]
pub struct Gated {
    /// The message to handle (the message itself, or the one a sealed frame held).
    pub deliver: Option<Envelope>,
    /// Messages to send back at once (the key exchange's replies), in order.
    pub replies: Vec<Envelope>,
}

impl Gated {
    fn deliver(msg: Envelope) -> Self {
        Self {
            deliver: Some(msg),
            replies: Vec::new(),
        }
    }
}

/// Relay-level answers: not part of a bridge, never sealed.
fn is_relay_level(t: MsgType) -> bool {
    matches!(t, MsgType::ReverseAccept | MsgType::ReverseReject)
}

fn is_setup(msg: &Envelope, session_id: &str) -> bool {
    matches!(&msg.payload, Payload::KeyExchange(k) if k.session_id == session_id)
}

impl SealGate {
    /// A bridge for `session_id` is being set up. With `must`, nothing but its key exchange may
    /// cross until [`install`](Self::install).
    pub fn begin(&self, session_id: String, must: bool) {
        *self.mode.lock().expect("seal gate") = Mode::Pending {
            session_id,
            must,
            scope: Scope::Bridge,
            responder: None,
        };
    }

    /// A whole direct (or pipe-relayed) connection is being sealed (wsh #155): `session_id` is the
    /// connection's. Nothing but its key exchange and the keepalive crosses until
    /// [`install`](Self::install).
    pub fn begin_session(&self, session_id: String) {
        *self.mode.lock().expect("seal gate") = Mode::Pending {
            session_id,
            must: true,
            scope: Scope::Session,
            responder: None,
        };
    }

    /// The HOST side of a sealed session (wsh #155): this connection's `KeyExchange` is answered
    /// here by `responder` (which holds the host key and the proven login key), and once the key
    /// exists the session is sealed. With `must`, nothing else but the keepalive is heard until
    /// then (`sealSession: 'require'`); without it a plain peer is served plainly and may seal
    /// whenever it likes (`'offer'`).
    pub fn begin_session_responder(&self, session_id: String, must: bool, responder: E2eResponder) {
        *self.mode.lock().expect("seal gate") = Mode::Pending {
            session_id,
            must,
            scope: Scope::Session,
            responder: Some(Box::new(responder)),
        };
    }

    /// The scope of the bridge being set up or sealed, if any.
    pub fn scope(&self) -> Option<Scope> {
        match &*self.mode.lock().expect("seal gate") {
            Mode::Pending { scope, .. } => Some(*scope),
            Mode::Sealed(b) => Some(b.scope()),
            _ => None,
        }
    }

    /// A message that arrived from the host itself (no `RelayForward`) on a SEALED SESSION:
    /// what to do with it. The keepalive stays plain; everything else must be a frame.
    pub fn incoming_direct(&self, msg: Envelope) -> Gated {
        let mut mode = self.mode.lock().expect("seal gate");
        let plain_ok = matches!(msg.msg_type, MsgType::Ping | MsgType::Pong);
        match &mut *mode {
            Mode::Off => Gated::deliver(msg),
            Mode::Failed => Gated::default(),
            Mode::Pending {
                session_id,
                must,
                scope,
                responder,
            } => {
                if is_setup(&msg, session_id) {
                    // The host side answers the key exchange itself, here, so the key is in place
                    // before the next frame is read (the initiator sends its first frame at once).
                    let Some(responder) = responder else {
                        return Gated::deliver(msg); // the initiator: a waiter takes it
                    };
                    let Payload::KeyExchange(k) = &msg.payload else {
                        return Gated::default();
                    };
                    return match responder.respond(k) {
                        Ok(r) => {
                            let replies = r
                                .replies
                                .into_iter()
                                .map(|k| Envelope {
                                    msg_type: MsgType::KeyExchange,
                                    payload: Payload::KeyExchange(k),
                                })
                                .collect();
                            if let Some(key) = r.key {
                                tracing::info!(hybrid = r.hybrid, "session sealed");
                                let (session, scope) = (session_id.clone(), *scope);
                                *mode = Mode::Sealed(SealedBridge::with_scope(
                                    key,
                                    session,
                                    RoleTag::Responder,
                                    scope,
                                ));
                                self.sealed.notify_one();
                            }
                            Gated {
                                deliver: None,
                                replies,
                            }
                        }
                        Err(e) => {
                            tracing::warn!("the sealed session's key exchange was refused: {e}");
                            *mode = Mode::Failed;
                            self.failed.notify_one();
                            Gated::default()
                        }
                    };
                }
                if plain_ok || !*must {
                    Gated::deliver(msg)
                } else {
                    tracing::warn!(msg_type = ?msg.msg_type, "dropping a plaintext message before the session is sealed");
                    Gated::default()
                }
            }
            Mode::Sealed(bridge) => {
                if plain_ok {
                    return Gated::deliver(msg);
                }
                if !bridge.is_frame(&msg) {
                    tracing::warn!(msg_type = ?msg.msg_type, "dropping a plaintext message on a sealed session");
                    return Gated::default();
                }
                match bridge.open(&msg) {
                    Ok(opened) => Gated::deliver(opened),
                    Err(e) => {
                        tracing::warn!("a sealed frame did not open ({e}): the session is closed");
                        *mode = Mode::Failed;
                        self.failed.notify_one();
                        Gated::default()
                    }
                }
            }
        }
    }

    /// The peer side: a bridge for `session_id` is set up by answering the operator's signed
    /// `KeyExchange` with `responder`; once the key exists the bridge is sealed.
    pub fn begin_responder(&self, session_id: String, must: bool, responder: E2eResponder) {
        *self.mode.lock().expect("seal gate") = Mode::Pending {
            session_id,
            must,
            scope: Scope::Bridge,
            responder: Some(Box::new(responder)),
        };
    }

    /// Resolves once the bridge was sealed by [`begin_responder`](Self::begin_responder)'s exchange.
    pub async fn wait_sealed(&self) {
        self.sealed.notified().await;
    }

    /// The key exists: from here the bridge is sealed.
    pub fn install(&self, bridge: SealedBridge) {
        *self.mode.lock().expect("seal gate") = Mode::Sealed(bridge);
    }

    /// The bridge is over (or never came up): plain again.
    pub fn end(&self) {
        *self.mode.lock().expect("seal gate") = Mode::Off;
    }

    /// Resolves once a sealed bridge has failed (a frame did not open).
    pub async fn wait_failed(&self) {
        self.failed.notified().await;
    }

    pub fn has_failed(&self) -> bool {
        matches!(*self.mode.lock().expect("seal gate"), Mode::Failed)
    }

    /// Should the dispatch loop end the connection when the bridge fails?
    pub fn set_close_on_failure(&self, on: bool) {
        self.close_on_failure.store(on, Ordering::Release);
    }

    pub fn closes_on_failure(&self) -> bool {
        self.close_on_failure.load(Ordering::Acquire)
    }

    /// Keep the sender of a forwarded message (see the field).
    pub fn set_tag_relay_origin(&self, on: bool) {
        self.tag_relay_origin.store(on, Ordering::Release);
    }

    pub fn tags_relay_origin(&self) -> bool {
        self.tag_relay_origin.load(Ordering::Acquire)
    }

    pub fn is_sealed(&self) -> bool {
        matches!(*self.mode.lock().expect("seal gate"), Mode::Sealed(_))
    }

    pub fn is_active(&self) -> bool {
        !matches!(*self.mode.lock().expect("seal gate"), Mode::Off)
    }

    /// An encoded frame about to leave: the frame to send, or `None` when it must not leave.
    pub fn outgoing(&self, frame: Vec<u8>) -> Option<Vec<u8>> {
        let mut mode = self.mode.lock().expect("seal gate");
        if matches!(*mode, Mode::Off) {
            return Some(frame);
        }
        let Ok(msg) = frame
            .get(4..)
            .map_or(Err(()), |b| decode_envelope(b).map_err(|_| ()))
        else {
            tracing::warn!("sealed bridge: dropping an undecodable outgoing frame");
            return None;
        };
        let session_scope = match &*mode {
            Mode::Pending { scope, .. } => *scope == Scope::Session,
            Mode::Sealed(b) => b.scope() == Scope::Session,
            _ => false,
        };
        if session_scope {
            // The whole session: everything but the keepalive (and the key exchange itself).
            if matches!(msg.msg_type, MsgType::Ping | MsgType::Pong) {
                return Some(frame);
            }
        } else if !(is_relay_forwardable(msg.msg_type)
            || is_relay_gateway_forwardable(msg.msg_type))
            || is_relay_level(msg.msg_type)
        {
            return Some(frame);
        }
        match &mut *mode {
            Mode::Off => Some(frame),
            Mode::Failed => None,
            Mode::Pending {
                session_id, must, ..
            } => {
                if is_setup(&msg, session_id) || !*must {
                    Some(frame)
                } else {
                    tracing::warn!(
                        msg_type = ?msg.msg_type,
                        "sealed bridge: nothing is sent over it before the key exists"
                    );
                    None
                }
            }
            Mode::Sealed(bridge) => {
                if is_setup(&msg, bridge.session_id()) {
                    return Some(frame); // a late key-exchange message of this bridge's setup
                }
                match bridge.seal(&msg).and_then(|sealed| frame_encode(&sealed)) {
                    Ok(sealed) => Some(sealed),
                    Err(e) => {
                        tracing::warn!("sealed bridge: could not seal an outgoing message: {e}");
                        None
                    }
                }
            }
        }
    }

    /// A message the relay forwarded (the inner message of a `RelayForward`): what to do with it.
    pub fn incoming_forwarded(&self, inner: Envelope) -> Gated {
        let mut mode = self.mode.lock().expect("seal gate");
        let drop = Gated::default();
        match &mut *mode {
            Mode::Off => Gated::deliver(inner),
            Mode::Failed => drop,
            Mode::Pending {
                session_id,
                must,
                responder,
                ..
            } => {
                if is_setup(&inner, session_id) {
                    let Some(responder) = responder else {
                        return Gated::deliver(inner); // the operator: a waiter takes it
                    };
                    let Payload::KeyExchange(msg) = &inner.payload else {
                        return drop;
                    };
                    return match responder.respond(msg) {
                        Ok(r) => {
                            let replies = r
                                .replies
                                .into_iter()
                                .map(|k| Envelope {
                                    msg_type: MsgType::KeyExchange,
                                    payload: Payload::KeyExchange(k),
                                })
                                .collect();
                            if let Some(key) = r.key {
                                tracing::info!(hybrid = r.hybrid, "bridge sealed");
                                let session = session_id.clone();
                                *mode = Mode::Sealed(SealedBridge::new(
                                    key,
                                    session,
                                    RoleTag::Responder,
                                ));
                                self.sealed.notify_one();
                            }
                            Gated {
                                deliver: None,
                                replies,
                            }
                        }
                        Err(e) => {
                            tracing::warn!("the sealed bridge's key exchange was refused: {e}");
                            *mode = Mode::Failed;
                            self.failed.notify_one();
                            drop
                        }
                    };
                }
                if !*must {
                    Gated::deliver(inner)
                } else {
                    tracing::warn!(
                        msg_type = ?inner.msg_type,
                        "dropping a plaintext message on a bridge that must be sealed"
                    );
                    drop
                }
            }
            Mode::Sealed(bridge) => {
                if !bridge.is_frame(&inner) {
                    tracing::warn!("dropping a plaintext message on a sealed bridge");
                    return drop;
                }
                match bridge.open(&inner) {
                    Ok(opened) => Gated::deliver(opened),
                    Err(e) => {
                        tracing::warn!("a sealed frame did not open ({e}): the bridge is closed");
                        *mode = Mode::Failed;
                        self.failed.notify_one();
                        drop
                    }
                }
            }
        }
    }

    /// A message that arrived NOT wrapped in a `RelayForward`: true when it must be dropped
    /// (a plain message a relay may forward, on a bridge that is sealed or must be).
    pub fn drop_unwrapped(&self, msg: &Envelope) -> bool {
        let mode = self.mode.lock().expect("seal gate");
        let guarded = match &*mode {
            Mode::Off => false,
            Mode::Pending { must, scope, .. } => *must && *scope == Scope::Bridge,
            Mode::Sealed(b) => b.scope() == Scope::Bridge,
            Mode::Failed => true,
        };
        guarded
            && (is_relay_forwardable(msg.msg_type) || is_relay_gateway_forwardable(msg.msg_type))
            && !is_relay_level(msg.msg_type)
            && !matches!(msg.msg_type, MsgType::RelayForward)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_frame::RoleTag;
    use wsh_core::messages::{ClosePayload, KeyExchangePayload, PingPongPayload};

    fn close(channel_id: u32) -> Envelope {
        Envelope {
            msg_type: MsgType::Close,
            payload: Payload::Close(ClosePayload { channel_id }),
        }
    }
    fn kex(session: &str) -> Envelope {
        Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: "X25519".into(),
                public_key: Some(vec![1; 32]),
                session_id: session.into(),
                kem_public_key: None,
                kem_ciphertext: None,
                signature: None,
            }),
        }
    }
    fn ping() -> Envelope {
        Envelope {
            msg_type: MsgType::Ping,
            payload: Payload::PingPong(PingPongPayload { id: 1 }),
        }
    }
    fn bridge(role: RoleTag) -> SealedBridge {
        SealedBridge::new([5; 32], "sid".into(), role)
    }

    #[test]
    fn off_changes_nothing() {
        let g = SealGate::default();
        let f = frame_encode(&close(1)).unwrap();
        assert_eq!(g.outgoing(f.clone()), Some(f));
        assert!(g.incoming_forwarded(close(1)).deliver.is_some());
        assert!(!g.drop_unwrapped(&close(1)));
    }

    #[test]
    fn until_the_key_exists_only_the_key_exchange_crosses() {
        let g = SealGate::default();
        g.begin("sid".into(), true);
        assert!(g.outgoing(frame_encode(&close(1)).unwrap()).is_none());
        assert!(g.outgoing(frame_encode(&kex("sid")).unwrap()).is_some());
        assert!(g.outgoing(frame_encode(&kex("other")).unwrap()).is_none());
        assert!(
            g.outgoing(frame_encode(&ping()).unwrap()).is_some(),
            "keepalive is not bridge traffic"
        );
        assert!(g.incoming_forwarded(close(1)).deliver.is_none());
        assert!(g.incoming_forwarded(kex("sid")).deliver.is_some());
        assert!(g.drop_unwrapped(&close(1)));
    }

    #[test]
    fn a_frame_that_does_not_open_closes_the_bridge() {
        let (op, host) = (SealGate::default(), SealGate::default());
        op.install(bridge(RoleTag::Initiator));
        host.install(bridge(RoleTag::Responder));
        let first = op.outgoing(frame_encode(&close(1)).unwrap()).unwrap();
        let second = op.outgoing(frame_encode(&close(2)).unwrap()).unwrap();
        let first = decode_envelope(&first[4..]).unwrap();
        let mut tampered = decode_envelope(&second[4..]).unwrap();
        if let Payload::EncryptedFrame(f) = &mut tampered.payload {
            f.ciphertext[0] ^= 1;
        }
        assert!(host.incoming_forwarded(first).deliver.is_some());
        assert!(host.incoming_forwarded(tampered).deliver.is_none());
        assert!(host.has_failed(), "tampering ends the bridge");
        assert!(
            host.incoming_forwarded(decode_envelope(&second[4..]).unwrap())
                .deliver
                .is_none(),
            "the genuine frame is not heard afterwards either"
        );
        assert!(
            host.outgoing(frame_encode(&close(3)).unwrap()).is_none(),
            "nothing leaves a failed bridge"
        );
    }

    /// Round 1 of a classical exchange from an initiator holding `secret`.
    fn round_one(session: &str, secret: &x25519_dalek::EphemeralSecret) -> Envelope {
        let public = x25519_dalek::PublicKey::from(secret);
        Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: "X25519".into(),
                public_key: Some(public.as_bytes().to_vec()),
                session_id: session.into(),
                kem_public_key: None,
                kem_ciphertext: None,
                signature: None,
            }),
        }
    }

    fn host_gate(must: bool) -> SealGate {
        let g = SealGate::default();
        g.begin_session_responder(
            "sid".into(),
            must,
            crate::e2e::E2eResponder::new(None, false, None, None),
        );
        g
    }

    #[test]
    fn a_host_that_requires_sealing_hears_only_the_key_exchange_and_the_keepalive_until_it_is_sealed(
    ) {
        let g = host_gate(true);
        assert!(
            g.incoming_direct(close(1)).deliver.is_none(),
            "plain is dropped"
        );
        assert!(
            g.incoming_direct(ping()).deliver.is_some(),
            "the keepalive is heard"
        );
        assert!(
            g.incoming_direct(kex("other")).deliver.is_none(),
            "a key exchange of another session is not this one's"
        );
        assert!(!g.is_sealed());
    }

    #[test]
    fn a_host_that_only_offers_serves_a_plain_peer_and_seals_when_asked() {
        let g = host_gate(false);
        assert!(
            g.incoming_direct(close(1)).deliver.is_some(),
            "a plain peer is served"
        );
        let f = frame_encode(&close(2)).unwrap();
        assert_eq!(g.outgoing(f.clone()), Some(f), "and spoken to plainly");
        let secret = x25519_dalek::EphemeralSecret::random();
        let gated = g.incoming_direct(round_one("sid", &secret));
        assert!(gated.deliver.is_none(), "the exchange is consumed");
        assert_eq!(gated.replies.len(), 1);
        assert!(g.is_sealed());
        assert_eq!(g.scope(), Some(Scope::Session));
    }

    #[test]
    fn a_host_session_is_sealed_both_ways_once_the_exchange_is_done() {
        let g = host_gate(true);
        let secret = x25519_dalek::EphemeralSecret::random();
        let gated = g.incoming_direct(round_one("sid", &secret));
        let Payload::KeyExchange(reply) = &gated.replies[0].payload else {
            panic!("a key exchange reply");
        };
        let theirs: [u8; 32] = reply.public_key.clone().unwrap().try_into().unwrap();
        let key = *secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(theirs))
            .as_bytes();
        let mut initiator =
            SealedBridge::with_scope(key, "sid".into(), RoleTag::Initiator, Scope::Session);
        // what the initiator seals opens at the host, and a replay of it closes the session
        let frame = initiator.seal(&close(9)).unwrap();
        let opened = g.incoming_direct(frame.clone()).deliver.unwrap();
        assert!(matches!(
            opened.payload,
            Payload::Close(ClosePayload { channel_id: 9 })
        ));
        assert!(g.incoming_direct(frame).deliver.is_none());
        assert!(g.has_failed(), "a replayed frame ends the session");
        // plain is not heard, and nothing leaves a failed session
        assert!(g.incoming_direct(close(1)).deliver.is_none());
        assert!(g.outgoing(frame_encode(&close(3)).unwrap()).is_none());
    }

    #[test]
    fn a_host_session_seals_what_it_sends_and_leaves_the_keepalive_plain() {
        let g = host_gate(true);
        let secret = x25519_dalek::EphemeralSecret::random();
        let gated = g.incoming_direct(round_one("sid", &secret));
        let Payload::KeyExchange(reply) = &gated.replies[0].payload else {
            panic!("a key exchange reply");
        };
        // the reply itself leaves as it is (the initiator has no key yet) ...
        let reply_frame = frame_encode(&gated.replies[0]).unwrap();
        assert_eq!(g.outgoing(reply_frame.clone()), Some(reply_frame));
        // ... everything else is a frame
        let out = g.outgoing(frame_encode(&close(5)).unwrap()).unwrap();
        assert_eq!(
            decode_envelope(&out[4..]).unwrap().msg_type,
            MsgType::EncryptedFrame
        );
        let p = frame_encode(&ping()).unwrap();
        assert_eq!(g.outgoing(p.clone()), Some(p));
        let _ = reply;
    }

    #[test]
    fn a_key_exchange_that_does_not_verify_ends_the_session() {
        let g = SealGate::default();
        let initiator = crate::e2e::InitiatorAuth {
            public_key: [7; 32],
            require: true,
        };
        g.begin_session_responder(
            "sid".into(),
            true,
            crate::e2e::E2eResponder::new(None, false, Some([1; 32]), Some(initiator)),
        );
        let secret = x25519_dalek::EphemeralSecret::random();
        // no initiator signature, and the host demands one
        let gated = g.incoming_direct(round_one("sid", &secret));
        assert!(gated.deliver.is_none() && gated.replies.is_empty());
        assert!(g.has_failed());
    }

    #[test]
    fn a_bridge_that_need_not_be_sealed_is_plain_until_it_is() {
        let g = SealGate::default();
        g.begin("sid".into(), false);
        assert!(g.outgoing(frame_encode(&close(1)).unwrap()).is_some());
        assert!(g.incoming_forwarded(close(1)).deliver.is_some());
        assert!(!g.drop_unwrapped(&close(1)));
    }

    #[test]
    fn sealed_traffic_is_sealed_both_ways_and_plain_is_dropped() {
        let (op, host) = (SealGate::default(), SealGate::default());
        op.install(bridge(RoleTag::Initiator));
        host.install(bridge(RoleTag::Responder));
        let wire = op.outgoing(frame_encode(&close(7)).unwrap()).unwrap();
        let sealed = decode_envelope(&wire[4..]).unwrap();
        assert_eq!(
            sealed.msg_type,
            MsgType::EncryptedFrame,
            "nothing readable on the wire"
        );
        let opened = host.incoming_forwarded(sealed.clone()).deliver.unwrap();
        assert!(matches!(
            opened.payload,
            Payload::Close(ClosePayload { channel_id: 7 })
        ));
        assert!(
            host.incoming_forwarded(sealed).deliver.is_none(),
            "a replay is dropped"
        );
        assert!(
            host.incoming_forwarded(close(7)).deliver.is_none(),
            "plain is dropped"
        );
        assert!(
            host.drop_unwrapped(&close(7)),
            "unwrapped plain is dropped too"
        );
        // keepalive and relay-level answers stay plain
        let p = frame_encode(&ping()).unwrap();
        assert_eq!(op.outgoing(p.clone()), Some(p));
    }
}
