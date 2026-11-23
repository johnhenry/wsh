//! The signed halves of the end-to-end `KeyExchange` (wsh #90, #117, #145). Byte-compatible with
//! `src/e2e-exchange.mjs`: the transcripts below are what both implementations sign and verify.
//!
//! `KeyExchange` carries ephemeral keys only, so by itself it protects against an observer, not
//! a relay that substitutes keys. Each side therefore signs, with its long-term Ed25519 identity,
//! a transcript binding a label, the session id, the algorithm the INITIATOR asked for and the
//! keys:
//!
//! ```text
//! responder = "wsh-e2e-keyexchange-v1\0"      || lp(session id) || lp(algorithm) || lp(initiator key) || lp(responder key)
//! initiator = "wsh-e2e-keyexchange-init-v1\0" || lp(session id) || lp(algorithm) || lp(initiator key) || lp(responder identity)
//! ```
//!
//! (`lp` = 4-byte big-endian length, then the bytes.) The labels differ so neither signature can
//! stand in for the other; the responder's covers both ephemeral keys, the initiator's names the
//! responder it means to reach.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Host feature (`ReverseAccept.features`): this host answers `KeyExchange` and seals/opens `EncryptedFrame`s.
pub const E2E_FEATURE: &str = "e2e";
/// Host feature: the host signs its `KeyExchange` reply, so the operator can authenticate it.
pub const E2E_SIGN_FEATURE: &str = "e2e-sign";
/// `KeyExchange.algorithm`: classical X25519.
pub const E2E_ALGORITHM_CLASSICAL: &str = "X25519";
/// `KeyExchange.algorithm`: hybrid X25519 + ML-KEM-768.
pub const E2E_ALGORITHM_HYBRID: &str = "X25519+ML-KEM-768";

const RESPONDER_LABEL: &[u8] = b"wsh-e2e-keyexchange-v1\0";
const INITIATOR_LABEL: &[u8] = b"wsh-e2e-keyexchange-init-v1\0";

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn transcript(label: &[u8], session_id: &str, algorithm: &str, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = label.to_vec();
    lp(&mut out, session_id.as_bytes());
    lp(&mut out, algorithm.as_bytes());
    lp(&mut out, a);
    lp(&mut out, b);
    out
}

/// The bytes a responder signs: `algorithm` is the INITIATOR's, not the reply's.
pub fn key_exchange_transcript(
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_key: &[u8],
) -> Vec<u8> {
    transcript(
        RESPONDER_LABEL,
        session_id,
        algorithm,
        initiator_key,
        responder_key,
    )
}

/// The bytes an initiator signs in its round-1 `KeyExchange`.
pub fn initiator_transcript(
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_identity: &[u8],
) -> Vec<u8> {
    transcript(
        INITIATOR_LABEL,
        session_id,
        algorithm,
        initiator_key,
        responder_identity,
    )
}

fn verify_with(key: &[u8], signature: Option<&[u8]>, data: &[u8]) -> bool {
    let (Ok(key), Some(Ok(sig))) = (
        <[u8; 32]>::try_from(key),
        signature.map(|s| Signature::from_slice(s)),
    ) else {
        return false;
    };
    VerifyingKey::from_bytes(&key).is_ok_and(|vk| vk.verify(data, &sig).is_ok())
}

/// Sign a responder's reply.
pub fn sign_key_exchange(
    key: &SigningKey,
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_key: &[u8],
) -> Vec<u8> {
    key.sign(&key_exchange_transcript(
        session_id,
        algorithm,
        initiator_key,
        responder_key,
    ))
    .to_bytes()
    .to_vec()
}

/// Sign an initiator's round-1 message.
pub fn sign_initiator(
    key: &SigningKey,
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_identity: &[u8],
) -> Vec<u8> {
    key.sign(&initiator_transcript(
        session_id,
        algorithm,
        initiator_key,
        responder_identity,
    ))
    .to_bytes()
    .to_vec()
}

/// Verify a responder's `KeyExchange.signature` against the host key the initiator meant to reach.
pub fn verify_key_exchange_signature(
    peer_identity: &[u8],
    signature: Option<&[u8]>,
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_key: &[u8],
) -> bool {
    verify_with(
        peer_identity,
        signature,
        &key_exchange_transcript(session_id, algorithm, initiator_key, responder_key),
    )
}

/// Verify an initiator's `KeyExchange.signature` against its (already proven) identity key.
pub fn verify_initiator_signature(
    initiator_identity: &[u8],
    signature: Option<&[u8]>,
    session_id: &str,
    algorithm: &str,
    initiator_key: &[u8],
    responder_identity: &[u8],
) -> bool {
    verify_with(
        initiator_identity,
        signature,
        &initiator_transcript(session_id, algorithm, initiator_key, responder_identity),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Printed by src/e2e-exchange.mjs for the same inputs, and by Node's crypto.sign (Ed25519 is
    // deterministic) with the seed 0x07 * 32.
    const KX: &str = "7773682d6532652d6b657965786368616e67652d7631000000000373696400000006583235353139000000200101010101010101010101010101010101010101010101010101010101010101000000200202020202020202020202020202020202020202020202020202020202020202";
    const INIT: &str = "7773682d6532652d6b657965786368616e67652d696e69742d76310000000003736964000000115832353531392b4d4c2d4b454d2d373638000000200101010101010101010101010101010101010101010101010101010101010101000000200303030303030303030303030303030303030303030303030303030303030303";
    const SIG_KX: &str = "1ad29c80fd0c8c3acdb55c8e142f7f0be8983eaf27464b7505b50da5ebdb7521c4c324957f658b4d96600449f0b9e8d387da05ce5ff6a5a8d8f0312c5cfa9c05";
    const SIG_INIT: &str = "bc543bbddb6b423af11a10b66f88d443552590c0987391957adec2f1a375775f316120b4ead289593ed43a20e42362e85d4518dfea66578821eb71015153ec0b";
    const PUB: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    #[test]
    fn transcripts_equal_the_bytes_the_js_implementation_produces() {
        assert_eq!(
            hex::encode(key_exchange_transcript(
                "sid", "X25519", &[1u8; 32], &[2u8; 32]
            )),
            KX
        );
        assert_eq!(
            hex::encode(initiator_transcript(
                "sid",
                "X25519+ML-KEM-768",
                &[1u8; 32],
                &[3u8; 32]
            )),
            INIT
        );
    }

    #[test]
    fn signatures_equal_the_ones_the_js_side_makes_and_verify_there_and_here() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), PUB);
        let kx = sign_key_exchange(&key, "sid", "X25519", &[1u8; 32], &[2u8; 32]);
        assert_eq!(hex::encode(&kx), SIG_KX);
        let init = sign_initiator(&key, "sid", "X25519+ML-KEM-768", &[1u8; 32], &[3u8; 32]);
        assert_eq!(hex::encode(&init), SIG_INIT);
        let public = key.verifying_key().to_bytes();
        assert!(verify_key_exchange_signature(
            &public,
            Some(&kx),
            "sid",
            "X25519",
            &[1u8; 32],
            &[2u8; 32]
        ));
        assert!(verify_initiator_signature(
            &public,
            Some(&init),
            "sid",
            "X25519+ML-KEM-768",
            &[1u8; 32],
            &[3u8; 32]
        ));
    }

    #[test]
    fn neither_half_passes_for_the_other_or_for_anything_it_does_not_cover() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        let public = key.verifying_key().to_bytes();
        let kx = sign_key_exchange(&key, "sid", "X25519", &[1u8; 32], &[2u8; 32]);
        let ok = |sig: &[u8], session: &str, alg: &str, a: &[u8], b: &[u8], who: &[u8]| {
            verify_key_exchange_signature(who, Some(sig), session, alg, a, b)
        };
        assert!(ok(&kx, "sid", "X25519", &[1u8; 32], &[2u8; 32], &public));
        assert!(!ok(&kx, "other", "X25519", &[1u8; 32], &[2u8; 32], &public));
        assert!(!ok(
            &kx,
            "sid",
            "X25519+ML-KEM-768",
            &[1u8; 32],
            &[2u8; 32],
            &public
        ));
        assert!(!ok(&kx, "sid", "X25519", &[9u8; 32], &[2u8; 32], &public));
        assert!(!ok(&kx, "sid", "X25519", &[1u8; 32], &[9u8; 32], &public));
        assert!(!ok(&kx, "sid", "X25519", &[1u8; 32], &[2u8; 32], &other));
        // the responder's signature is not an initiator signature over the same fields, and vice versa
        assert!(!verify_initiator_signature(
            &public,
            Some(&kx),
            "sid",
            "X25519",
            &[1u8; 32],
            &[2u8; 32]
        ));
        assert!(!verify_key_exchange_signature(
            &public, None, "sid", "X25519", &[1u8; 32], &[2u8; 32]
        ));
        assert!(!verify_key_exchange_signature(
            &public,
            Some(&kx[..63]),
            "sid",
            "X25519",
            &[1u8; 32],
            &[2u8; 32]
        ));
    }
}
