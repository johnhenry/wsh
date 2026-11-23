//! End-to-end encryption key exchange (wsh #18: hybrid X25519 + ML-KEM-768).
//!
//! Mirrors `@johnhenry/wsh`'s `src/client.mjs` `initiateE2E` /
//! `combineHybridSecret` / `mlkem.mjs` byte-for-byte, so a Rust `WshClient`
//! and a JS `WshClient` can complete the same wire protocol and land on the
//! same AES-256-GCM key. See `WshClient::initiate_e2e` in `client.rs` for
//! the actual round-trip driver; this module holds the pieces that don't
//! need transport/dispatch-loop access: algorithm name constants, the
//! result type, and the HKDF combine step.
//!
//! Protocol summary (see `client.rs::initiate_e2e` doc comment for the
//! full round-by-round version):
//! - Round 1: both sides generate an ephemeral X25519 key pair (and, for
//!   hybrid mode, a fresh ML-KEM-768 key pair too) and exchange them in a
//!   `KeyExchange` message.
//! - Each side derives the X25519 ECDH shared secret from its own private
//!   key and the peer's public key.
//! - If hybrid mode is active on both sides (both round-1 messages carried
//!   a `kem_public_key`), the two ephemeral X25519 public keys are compared
//!   byte-lexicographically -- Rust's `Ord` on `&[u8]`/`Vec<u8>` already
//!   compares elementwise then by length, exactly matching the JS
//!   `compareBytes` helper, so no separate comparator is needed here --
//!   and whichever side's own bytes sort lower is the "encapsulator": it
//!   encapsulates against the peer's `kem_public_key` and sends a second
//!   `KeyExchange` carrying only `kem_ciphertext`. The other side (the
//!   "decapsulator") waits for that message and decapsulates.
//! - The two 32-byte outputs (X25519 ECDH secret, ML-KEM-768 shared
//!   secret) are combined via HKDF-SHA256 into the final 32-byte
//!   AES-256-GCM key (see `combine_hybrid_secret`). In classical mode (or
//!   if hybrid wasn't actually used), the X25519 ECDH output alone is the
//!   key, with no HKDF step.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey, Kem, KeyExport, MlKem768, TryKeyInit};
use ring::hkdf;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::KeyExchangePayload;

/// `algorithm` value for classical-only (X25519 ECDH) E2E key exchange.
pub const ALGORITHM_X25519: &str = "X25519";

/// `algorithm` value for hybrid classical+post-quantum (X25519 + ML-KEM-768)
/// E2E key exchange.
pub const ALGORITHM_HYBRID: &str = "X25519+ML-KEM-768";

/// Domain-separation info string for the hybrid-secret HKDF-SHA256 combine
/// step. Must match `@johnhenry/wsh`'s `combineHybridSecret` exactly --
/// getting this (or the IKM field order below) wrong would silently break
/// interop with real JS peers even though Rust-to-Rust tests would still
/// pass.
const HYBRID_COMBINE_INFO: &[u8] = b"wsh-hybrid-e2e-v1";

/// Result of a completed `WshClient::initiate_e2e` key exchange.
#[derive(Debug, Clone)]
pub struct E2eKeyExchange {
    /// The peer's ephemeral X25519 public key (raw 32 bytes), as sent in
    /// its round-1 `KeyExchange` message.
    pub peer_public_key: Vec<u8>,
    /// The derived AES-256-GCM key: the raw X25519 ECDH output in
    /// classical mode, or the HKDF-SHA256-combined X25519+ML-KEM-768
    /// output in hybrid mode (see `hybrid`).
    pub shared_secret: [u8; 32],
    /// Whether hybrid (X25519 + ML-KEM-768) mode actually took effect.
    /// `false` means either classical mode was requested, or hybrid was
    /// requested but the peer's round-1 message didn't include a
    /// `kem_public_key` (it doesn't support hybrid mode) -- algorithm
    /// agility, not a hard cutover.
    pub hybrid: bool,
    /// Whether the peer signed its half and the signature verified against `verify_peer`.
    pub peer_authenticated: bool,
}

/// Options of [`crate::WshClient::initiate_e2e_with`].
#[derive(Default, Clone, Copy)]
pub struct E2eOptions<'a> {
    /// The peer's Ed25519 public key: require its signed reply to verify against it.
    pub verify_peer: Option<[u8; 32]>,
    /// Sign this (initiator) half with the operator's key. Send only to a peer that stated `e2e-sealed`.
    pub sign_as: Option<&'a SigningKey>,
    /// The responder's identity key bound into the initiator signature (default: `verify_peer`).
    pub responder_identity: Option<[u8; 32]>,
}

/// Combine the classical (X25519 ECDH) and post-quantum (ML-KEM-768) key
/// exchange outputs into one 32-byte AES-256-GCM key via HKDF-SHA256, so
/// the final key is only as weak as the *stronger* of the two primitives
/// if either is ever broken.
///
/// `IKM = x25519_secret || kem_secret` (64 bytes, in that order), salt =
/// empty, info = `"wsh-hybrid-e2e-v1"`, output length 32 bytes. Mirrors
/// `@johnhenry/wsh`'s `combineHybridSecret` (`src/client.mjs`) byte-for-byte.
pub fn combine_hybrid_secret(
    x25519_secret: &[u8],
    kem_shared_secret: &[u8],
) -> WshResult<[u8; 32]> {
    let mut ikm = Vec::with_capacity(x25519_secret.len() + kem_shared_secret.len());
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(kem_shared_secret);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&ikm);
    let okm = prk
        .expand(&[HYBRID_COMBINE_INFO], hkdf::HKDF_SHA256)
        .map_err(|_| WshError::Other("HKDF-SHA256 expand failed".into()))?;

    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .map_err(|_| WshError::Other("HKDF-SHA256 fill failed".into()))?;
    Ok(out)
}

/// The operator's identity as a responder knows it (already proven by a `ReverseProof`): a
/// round-1 `signature` is verified against it, and with `require` a missing one refuses the
/// exchange (wsh #117).
#[derive(Debug, Clone)]
pub struct InitiatorAuth {
    pub public_key: [u8; 32],
    pub require: bool,
}

/// What [`E2eResponder::respond`] produced.
#[derive(Debug, Default)]
pub struct Responded {
    /// Messages to send back, in this order (the round-1 reply, then for a hybrid exchange in
    /// which this side encapsulates, the ciphertext).
    pub replies: Vec<KeyExchangePayload>,
    /// The derived AES-256-GCM key, once the exchange is complete.
    pub key: Option<[u8; 32]>,
    pub hybrid: bool,
}

struct PendingHybrid {
    shared_bits: [u8; 32],
    local_dk: <MlKem768 as Kem>::DecapsulationKey,
    created: std::time::Instant,
}

const MAX_PENDING: usize = 8;
const PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(15);

/// The responder side of `KeyExchange` (wsh #90, #117), for a host. One instance per bridge.
/// Mirrors `E2EResponder` in `src/e2e-exchange.mjs`: a round-1 message gets an ephemeral key,
/// a (signed) reply and -- classical, or hybrid with this side as encapsulator -- the key at
/// once; as decapsulator it waits for the round-2 ciphertext.
pub struct E2eResponder {
    sign_key: Option<SigningKey>,
    hybrid: bool,
    identity: Option<[u8; 32]>,
    initiator: Option<InitiatorAuth>,
    pending: HashMap<String, PendingHybrid>,
}

impl E2eResponder {
    /// `sign_key`: given, the reply is signed. `identity`: this responder's public identity key
    /// (what an initiator signs as `responder_identity`). `hybrid`: offer X25519+ML-KEM-768 when asked.
    pub fn new(
        sign_key: Option<SigningKey>,
        hybrid: bool,
        identity: Option<[u8; 32]>,
        initiator: Option<InitiatorAuth>,
    ) -> Self {
        Self {
            sign_key,
            hybrid,
            identity,
            initiator,
            pending: HashMap::new(),
        }
    }

    /// Forget unfinished exchanges (the bridge ended).
    pub fn close(&mut self) {
        self.pending.clear();
    }

    pub fn respond(&mut self, msg: &KeyExchangePayload) -> WshResult<Responded> {
        if msg.session_id.is_empty() {
            return Err(WshError::InvalidMessage(
                "KeyExchange without a session_id".into(),
            ));
        }
        self.pending
            .retain(|_, p| p.created.elapsed() < PENDING_TTL);
        if msg.public_key.is_none() && msg.kem_ciphertext.is_some() {
            return self.finish(msg);
        }
        self.begin(msg)
    }

    fn begin(&mut self, msg: &KeyExchangePayload) -> WshResult<Responded> {
        let algorithm = msg.algorithm.as_str();
        if algorithm != ALGORITHM_X25519 && algorithm != ALGORITHM_HYBRID {
            return Err(WshError::InvalidMessage(format!(
                "unsupported E2E algorithm {algorithm:?}"
            )));
        }
        let peer_pub: [u8; 32] = msg
            .public_key
            .as_deref()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                WshError::InvalidMessage(
                    "KeyExchange public_key must be a 32-byte X25519 key".into(),
                )
            })?;
        let peer_kem = msg
            .kem_public_key
            .as_deref()
            .and_then(|k| EncapsulationKey::<MlKem768>::new_from_slice(k).ok());
        let want_hybrid = algorithm == ALGORITHM_HYBRID && self.hybrid && peer_kem.is_some();

        // The initiator's half (wsh #117): signed by the operator key this bridge already proved.
        if let Some(auth) = &self.initiator {
            match msg.signature.as_deref() {
                Some(sig) => {
                    let verified = self.identity.is_some_and(|identity| {
                        wsh_core::e2e_exchange::verify_initiator_signature(
                            &auth.public_key,
                            Some(sig),
                            &msg.session_id,
                            algorithm,
                            &peer_pub,
                            &identity,
                        )
                    });
                    if !verified {
                        return Err(WshError::AuthFailed(
                            "KeyExchange initiator signature does not verify".into(),
                        ));
                    }
                }
                None if auth.require => {
                    return Err(WshError::AuthFailed(
                        "KeyExchange without the initiator signature this host requires".into(),
                    ));
                }
                None => {}
            }
        }

        // A fresh exchange for this session replaces an unfinished one.
        self.pending.remove(&msg.session_id);
        while self.pending.len() >= MAX_PENDING {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => self.pending.remove(&k),
                None => break,
            };
        }

        let secret = EphemeralSecret::random();
        let local_pub = *X25519PublicKey::from(&secret).as_bytes();
        let local_kem = want_hybrid.then(MlKem768::generate_keypair);
        let hybrid = local_kem.is_some();

        let mut reply = KeyExchangePayload {
            algorithm: if hybrid {
                ALGORITHM_HYBRID
            } else {
                ALGORITHM_X25519
            }
            .to_string(),
            public_key: Some(local_pub.to_vec()),
            session_id: msg.session_id.clone(),
            kem_public_key: local_kem.as_ref().map(|(_dk, ek)| ek.to_bytes().to_vec()),
            kem_ciphertext: None,
            signature: None,
        };
        if let Some(key) = &self.sign_key {
            // the transcript carries the INITIATOR's algorithm string, not this reply's
            reply.signature = Some(wsh_core::e2e_exchange::sign_key_exchange(
                key,
                &msg.session_id,
                algorithm,
                &peer_pub,
                &local_pub,
            ));
        }
        let mut replies = vec![reply];

        let shared_bits = *secret
            .diffie_hellman(&X25519PublicKey::from(peer_pub))
            .as_bytes();
        let Some((local_dk, _)) = local_kem else {
            return Ok(Responded {
                replies,
                key: Some(shared_bits),
                hybrid: false,
            });
        };
        let peer_ek = peer_kem.expect("hybrid needs the peer's kem key");
        if local_pub.as_slice() < peer_pub.as_slice() {
            // The lower key encapsulates against the other side's ML-KEM key.
            let (ciphertext, shared) = peer_ek.encapsulate();
            replies.push(KeyExchangePayload {
                algorithm: ALGORITHM_HYBRID.to_string(),
                public_key: None,
                session_id: msg.session_id.clone(),
                kem_public_key: None,
                kem_ciphertext: Some(ciphertext.to_vec()),
                signature: None,
            });
            let kem_secret: [u8; 32] = shared
                .as_slice()
                .try_into()
                .map_err(|_| WshError::Other("ML-KEM-768 shared secret was not 32 bytes".into()))?;
            return Ok(Responded {
                replies,
                key: Some(combine_hybrid_secret(&shared_bits, &kem_secret)?),
                hybrid: true,
            });
        }
        // The higher key decapsulates: wait for the peer's ciphertext.
        self.pending.insert(
            msg.session_id.clone(),
            PendingHybrid {
                shared_bits,
                local_dk,
                created: std::time::Instant::now(),
            },
        );
        Ok(Responded {
            replies,
            key: None,
            hybrid: true,
        })
    }

    fn finish(&mut self, msg: &KeyExchangePayload) -> WshResult<Responded> {
        let pending = self.pending.remove(&msg.session_id).ok_or_else(|| {
            WshError::InvalidMessage(
                "unexpected KeyExchange ciphertext (no hybrid exchange in progress for this session)"
                    .into(),
            )
        })?;
        let ciphertext = msg.kem_ciphertext.as_deref().unwrap_or_default();
        let shared = pending
            .local_dk
            .decapsulate_slice(ciphertext)
            .map_err(|_| WshError::InvalidMessage("invalid peer kem_ciphertext".into()))?;
        let kem_secret: [u8; 32] = shared
            .as_slice()
            .try_into()
            .map_err(|_| WshError::Other("ML-KEM-768 shared secret was not 32 bytes".into()))?;
        Ok(Responded {
            replies: Vec::new(),
            key: Some(combine_hybrid_secret(&pending.shared_bits, &kem_secret)?),
            hybrid: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_hybrid_secret_is_deterministic() {
        let x25519 = [0x11u8; 32];
        let kem = [0x22u8; 32];
        let a = combine_hybrid_secret(&x25519, &kem).unwrap();
        let b = combine_hybrid_secret(&x25519, &kem).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn combine_hybrid_secret_differs_from_either_input_alone() {
        let x25519 = [0x11u8; 32];
        let kem = [0x22u8; 32];
        let combined = combine_hybrid_secret(&x25519, &kem).unwrap();
        assert_ne!(combined, x25519);
        assert_ne!(combined, kem);
    }

    #[test]
    fn combine_hybrid_secret_is_sensitive_to_field_order() {
        // IKM = x25519 || kem, not kem || x25519 -- swapping the order
        // must change the output, since a real interop bug here would be
        // silent (both Rust-to-Rust ends would still agree with
        // themselves, just not with a real JS peer).
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let forward = combine_hybrid_secret(&a, &b).unwrap();
        let swapped = combine_hybrid_secret(&b, &a).unwrap();
        assert_ne!(forward, swapped);
    }

    #[test]
    fn combine_hybrid_secret_is_sensitive_to_either_input() {
        let base_x = [0x11u8; 32];
        let base_kem = [0x22u8; 32];
        let baseline = combine_hybrid_secret(&base_x, &base_kem).unwrap();

        let mut other_x = base_x;
        other_x[0] ^= 0xff;
        assert_ne!(
            combine_hybrid_secret(&other_x, &base_kem).unwrap(),
            baseline
        );

        let mut other_kem = base_kem;
        other_kem[0] ^= 0xff;
        assert_ne!(
            combine_hybrid_secret(&base_x, &other_kem).unwrap(),
            baseline
        );
    }
}
