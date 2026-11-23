//! A sealed bridge (wsh #117, #145): everything two endpoints say to each other across a relay,
//! sealed under a key they agreed with a signed `KeyExchange` whose `session_id` is the bridge's,
//! so the relay carries ciphertext it cannot read, forge, replay or reorder -- and, because a
//! relay can stamp any `from_fingerprint` on a PLAIN message, cannot make a peer act for an
//! operator that is not there.
//!
//! Byte-compatible with `src/bridge-seal.mjs`: each message that would cross the bridge is
//! CBOR-encoded and sealed with the same AES-256-GCM framing as session data
//! ([`crate::e2e_frame`]: a strict send counter, a role tag per direction, `session_id` as AAD)
//! into an `EncryptedFrame` with `channel_id` 0 (real channels start at 1). The receiver opens it
//! and handles the inner message as if it had arrived plain; a plain message on a sealed bridge
//! is dropped.

use crate::e2e_frame::{open_frame, seal_frame, RoleTag};
use wsh_core::messages::{EncryptedFramePayload, Envelope, MsgType, Payload};
use wsh_core::{cbor_encode, decode_envelope, WshError, WshResult};

/// `EncryptedFrame.channel_id` of a bridge-level frame.
pub const BRIDGE_CHANNEL_ID: u32 = 0;

/// What a sealed bridge may carry (wsh #155).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A reverse bridge across a relay: only what a relay may forward.
    Bridge,
    /// A whole direct or pipe-relayed connection: any message after login.
    Session,
}

/// One direction pair of a sealed bridge.
pub struct SealedBridge {
    scope: Scope,
    key: [u8; 32],
    session_id: String,
    send_tag: RoleTag,
    recv_tag: RoleTag,
    send_counter: u64,
    recv_counter: u64,
}

impl std::fmt::Debug for SealedBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the key
        f.debug_struct("SealedBridge")
            .field("session_id", &self.session_id)
            .field("send_counter", &self.send_counter)
            .field("recv_counter", &self.recv_counter)
            .finish()
    }
}

impl SealedBridge {
    /// `role` is this side's: [`RoleTag::Initiator`] is the operator, [`RoleTag::Responder`] the peer.
    pub fn new(key: [u8; 32], session_id: String, role: RoleTag) -> Self {
        Self::with_scope(key, session_id, role, Scope::Bridge)
    }

    pub fn with_scope(key: [u8; 32], session_id: String, role: RoleTag, scope: Scope) -> Self {
        Self {
            scope,
            key,
            session_id,
            send_tag: role,
            recv_tag: role.peer(),
            send_counter: 0,
            recv_counter: 0,
        }
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Is `msg` a bridge-level frame of this bridge?
    pub fn is_frame(&self, msg: &Envelope) -> bool {
        matches!(&msg.payload, Payload::EncryptedFrame(f)
            if f.channel_id == BRIDGE_CHANNEL_ID && f.session_id == self.session_id)
    }

    /// Seal one message. Calls must be sent in call order (the counter is strict).
    pub fn seal(&mut self, msg: &Envelope) -> WshResult<Envelope> {
        let plaintext = cbor_encode(msg)?;
        let (nonce, ciphertext) = seal_frame(
            &self.key,
            &self.session_id,
            self.send_tag,
            self.send_counter,
            &plaintext,
        )?;
        self.send_counter += 1;
        Ok(Envelope {
            msg_type: MsgType::EncryptedFrame,
            payload: Payload::EncryptedFrame(EncryptedFramePayload {
                channel_id: BRIDGE_CHANNEL_ID,
                nonce,
                ciphertext,
                session_id: self.session_id.clone(),
            }),
        })
    }

    /// Open one frame. A replayed, reordered, forged or foreign frame is an error and does not
    /// consume a counter. The inner message is always one a relay may forward.
    pub fn open(&mut self, frame: &Envelope) -> WshResult<Envelope> {
        let Payload::EncryptedFrame(f) = &frame.payload else {
            return Err(WshError::Other("not a frame of this bridge".into()));
        };
        if !self.is_frame(frame) {
            return Err(WshError::Other("not a frame of this bridge".into()));
        }
        let plain = open_frame(
            &self.key,
            &self.session_id,
            self.recv_counter,
            &f.nonce,
            &f.ciphertext,
        )?;
        // The role tag is part of the nonce: a frame of our own direction, reflected back, fails here.
        if f.nonce[8..] != self.recv_tag.bytes() {
            return Err(WshError::Other(
                "sealed frame carries the wrong role tag (reflected?)".into(),
            ));
        }
        self.recv_counter += 1;
        let inner = decode_envelope(&plain)?;
        if matches!(inner.msg_type, MsgType::RelayForward)
            || (self.scope == Scope::Bridge
                && !wsh_core::messages::is_relay_forwardable(inner.msg_type))
        {
            return Err(WshError::Other(
                "sealed message of a type that may not cross a bridge".into(),
            ));
        }
        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsh_core::messages::OpenPayload;

    fn open_msg(command: &str) -> Envelope {
        Envelope {
            msg_type: MsgType::Open,
            payload: Payload::Open(OpenPayload {
                kind: wsh_core::ChannelKind::Exec,
                command: Some(command.into()),
                cols: None,
                rows: None,
                env: None,
                stdio: None,
                target: None,
            }),
        }
    }

    fn pair() -> (SealedBridge, SealedBridge) {
        (
            SealedBridge::new([9u8; 32], "sid".into(), RoleTag::Initiator),
            SealedBridge::new([9u8; 32], "sid".into(), RoleTag::Responder),
        )
    }

    #[test]
    fn a_frame_the_js_implementation_sealed_opens_here() {
        // src/bridge-seal.mjs, key 0x09 * 32, session "sid", initiator, counter 0, Open { exec, "ls", 80x24 }
        let nonce = hex::decode("0000000000000000696e6974").unwrap();
        let ciphertext = hex::decode("d527073ce3dc9c7b1a2e9212a238a6450fa943c205db70b1395b8b5882fdc1bf8d65f0cd77a3ff3203a66e3d4ab55c16db1ca6fc0f514177e910").unwrap();
        let frame = Envelope {
            msg_type: MsgType::EncryptedFrame,
            payload: Payload::EncryptedFrame(EncryptedFramePayload {
                channel_id: 0,
                nonce,
                ciphertext,
                session_id: "sid".into(),
            }),
        };
        let (_, mut responder) = pair();
        let opened = responder.open(&frame).expect("JS frame opens");
        let Payload::Open(open) = opened.payload else {
            panic!("an Open")
        };
        assert_eq!(open.command.as_deref(), Some("ls"));
    }

    #[test]
    fn a_frame_sealed_here_has_the_nonce_the_js_implementation_builds() {
        let (mut initiator, _) = pair();
        let frame = initiator.seal(&open_msg("ls")).unwrap();
        let Payload::EncryptedFrame(f) = frame.payload else {
            panic!()
        };
        assert_eq!(f.channel_id, 0);
        assert_eq!(hex::encode(&f.nonce), "0000000000000000696e6974");
    }

    #[test]
    fn frames_open_in_order_and_a_replay_a_reorder_or_a_reflection_does_not() {
        let (mut a, mut b) = pair();
        let f0 = a.seal(&open_msg("zero")).unwrap();
        let f1 = a.seal(&open_msg("one")).unwrap();
        assert!(b.open(&f1).is_err(), "out of order");
        assert!(b.open(&f0).is_ok());
        assert!(b.open(&f0).is_err(), "replayed");
        assert!(
            b.open(&f1).is_ok(),
            "a refused frame did not consume a counter"
        );
        // own frame reflected back at the sender
        let f2 = a.seal(&open_msg("two")).unwrap();
        let mut a_again = SealedBridge::new([9u8; 32], "sid".into(), RoleTag::Initiator);
        // counters aside, the role tag alone refuses it
        let _ = a_again.seal(&open_msg("x")).unwrap();
        let _ = a_again.seal(&open_msg("y")).unwrap();
        assert!(a_again.open(&f2).is_err(), "reflected");
    }

    #[test]
    fn a_tampered_foreign_or_plain_message_is_refused() {
        let (mut a, mut b) = pair();
        let mut f = a.seal(&open_msg("ls")).unwrap();
        if let Payload::EncryptedFrame(p) = &mut f.payload {
            p.ciphertext[0] ^= 1;
        }
        assert!(b.open(&f).is_err(), "tampered");
        // the same bytes under another session id
        let mut c = SealedBridge::new([9u8; 32], "other".into(), RoleTag::Responder);
        let good = a.seal(&open_msg("ls")).unwrap();
        assert!(c.open(&good).is_err(), "another bridge");
        assert!(b.open(&open_msg("plain")).is_err(), "plain");
        // a frame on a real channel is not a bridge frame
        let mut on_channel = good.clone();
        if let Payload::EncryptedFrame(p) = &mut on_channel.payload {
            p.channel_id = 1;
        }
        assert!(!b.is_frame(&on_channel));
    }

    #[test]
    fn a_sealed_message_that_may_not_cross_a_bridge_is_refused() {
        let (mut a, mut b) = pair();
        let forbidden = Envelope {
            msg_type: MsgType::Ping,
            payload: Payload::PingPong(wsh_core::messages::PingPongPayload { id: 1 }),
        };
        let frame = a.seal(&forbidden).unwrap();
        assert!(b.open(&frame).is_err());
    }
}
