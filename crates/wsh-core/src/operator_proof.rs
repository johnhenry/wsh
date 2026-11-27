//! The operator proves its identity to the PEER (wsh #117, #145). Byte-compatible with
//! `src/operator-proof.mjs`; the wire shape is `ReverseChallenge` (0x58) / `ReverseProof` (0x59)
//! and `ReverseConnect.features`.
//!
//! ```text
//! operator -> relay -> peer   ReverseConnect { features: ["operator-proof"] }
//! peer -> relay -> operator   ReverseChallenge { public_key, operator_fingerprint, nonce, session_id, signature }
//! operator -> relay -> peer   ReverseProof { public_key, username, nonce, session_id, signature }
//! peer: verifies, THEN decides whether to accept (the operator is `proven`)
//! ```
//!
//! Both signatures are Ed25519 over a labelled, length-prefixed byte string (not a hash):
//! `challenge = "wsh-reverse-challenge-v1\0" || lp(peer key) || lp(operator fingerprint) || lp(nonce) || lp(session id)`;
//! `proof = "wsh-operator-proof-v1\0" || lp(peer key) || lp(operator key) || lp(username) || lp(nonce) || lp(session id)`.
//!
//! This proves who was at the other end when the bridge was set up. A relay can still stamp
//! that identity on a plain message afterwards; closing that is the sealed bridge.

use crate::identity::fingerprint;
use crate::messages::{ReverseChallengePayload, ReverseProofPayload};
use crate::{WshError, WshResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

/// `ServerHello.features` of a relay that carries the proof messages, and
/// `ReverseConnect.features` of an operator that answers a challenge.
pub const OPERATOR_PROOF_FEATURE: &str = "operator-proof";
/// `ReverseAccept.features` of a peer that takes a signed initiator half and a sealed bridge.
pub const E2E_SEALED_FEATURE: &str = "e2e-sealed";
pub const NONCE_LENGTH: usize = 32;
/// What a host lists in its REGISTERED capabilities when it reads a signed statement of `gateway-lossless-close` in an operator's proof
/// (wsh #318): an operator signs the statement (a `wsh-operator-proof-v2` proof) only for a peer that lists this.
pub const GATEWAY_LOSSLESS_SIGNED_FEATURE: &str = "gateway-lossless-close-signed";
/// The one statement a proof can carry (wsh #318); equals [`crate::gateway_credit::GATEWAY_LOSSLESS_FEATURE`].
const SIGNABLE: &[&str] = &[crate::gateway_credit::GATEWAY_LOSSLESS_FEATURE];

const CHALLENGE_LABEL: &[u8] = b"wsh-reverse-challenge-v1\0";
const PROOF_LABEL: &[u8] = b"wsh-operator-proof-v1\0";
const PROOF_LABEL_V2: &[u8] = b"wsh-operator-proof-v2\0";

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes a peer signs in a `ReverseChallenge`.
pub fn challenge_transcript(
    peer_public_key: &[u8],
    operator_fingerprint: &str,
    nonce: &[u8],
    session_id: &str,
) -> Vec<u8> {
    let mut out = CHALLENGE_LABEL.to_vec();
    lp(&mut out, peer_public_key);
    lp(&mut out, operator_fingerprint.as_bytes());
    lp(&mut out, nonce);
    lp(&mut out, session_id.as_bytes());
    out
}

/// The bytes an operator signs in a `ReverseProof`.
pub fn proof_transcript(
    peer_public_key: &[u8],
    operator_public_key: &[u8],
    username: &str,
    nonce: &[u8],
    session_id: &str,
) -> Vec<u8> {
    proof_transcript_with(
        peer_public_key,
        operator_public_key,
        username,
        nonce,
        session_id,
        &[],
    )
}

/// [`proof_transcript`] with the statements the operator makes about this bridge (wsh #318): with none, the unchanged v1 bytes; with some, the
/// `wsh-operator-proof-v2` label and each statement length-prefixed, sorted, after the session id. Byte-compatible with `src/operator-proof.mjs`.
pub fn proof_transcript_with(
    peer_public_key: &[u8],
    operator_public_key: &[u8],
    username: &str,
    nonce: &[u8],
    session_id: &str,
    features: &[&str],
) -> Vec<u8> {
    let mut out = if features.is_empty() {
        PROOF_LABEL.to_vec()
    } else {
        PROOF_LABEL_V2.to_vec()
    };
    lp(&mut out, peer_public_key);
    lp(&mut out, operator_public_key);
    lp(&mut out, username.as_bytes());
    lp(&mut out, nonce);
    lp(&mut out, session_id.as_bytes());
    let mut sorted: Vec<&str> = features.to_vec();
    sorted.sort_unstable();
    for f in sorted {
        lp(&mut out, f.as_bytes());
    }
    out
}

fn verify_with(key: &[u8], signature: &[u8], data: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    let (Ok(vk), Ok(sig)) = (
        VerifyingKey::from_bytes(&key),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    vk.verify(data, &sig).is_ok()
}

/// What a peer remembers about the challenge it issued, to check the proof against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: Vec<u8>,
    pub session_id: String,
    pub peer_public_key: [u8; 32],
}

/// Peer side: make a challenge for the operator `operator_fingerprint` (as the relay stamped it).
/// `target_fingerprint` is where the relay should send it (the operator; the relay re-stamps it).
pub fn create_challenge(
    key: &SigningKey,
    target_fingerprint: &str,
    operator_fingerprint: &str,
) -> (ReverseChallengePayload, IssuedChallenge) {
    let mut nonce = vec![0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    let session_id = hex::encode(id);
    let public_key = key.verifying_key().to_bytes();
    let signature = key
        .sign(&challenge_transcript(
            &public_key,
            operator_fingerprint,
            &nonce,
            &session_id,
        ))
        .to_bytes()
        .to_vec();
    (
        ReverseChallengePayload {
            target_fingerprint: target_fingerprint.to_string(),
            public_key: public_key.to_vec(),
            operator_fingerprint: operator_fingerprint.to_string(),
            nonce: nonce.clone(),
            session_id: session_id.clone(),
            signature,
        },
        IssuedChallenge {
            nonce,
            session_id,
            peer_public_key: public_key,
        },
    )
}

/// A challenge the operator has verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChallenge {
    pub peer_public_key: [u8; 32],
    pub peer_fingerprint: String,
    pub nonce: Vec<u8>,
    pub session_id: String,
}

/// Operator side: check a `ReverseChallenge`. `target` is the peer fingerprint (or a prefix of it)
/// that was asked for; `own_fingerprint` is this operator's own.
pub fn verify_challenge(
    msg: &ReverseChallengePayload,
    target: &str,
    own_fingerprint: &str,
) -> WshResult<VerifiedChallenge> {
    let fail = |why: &str| WshError::AuthFailed(format!("reverse challenge refused: {why}"));
    let peer_public_key: [u8; 32] = msg
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| fail("malformed"))?;
    if msg.nonce.len() != NONCE_LENGTH
        || msg.session_id.is_empty()
        || msg.session_id.len() > 256
        || msg.operator_fingerprint.is_empty()
        || msg.operator_fingerprint.len() > 256
    {
        return Err(fail("malformed"));
    }
    let peer_fingerprint = fingerprint(&peer_public_key);
    if target.is_empty() || !peer_fingerprint.starts_with(target) {
        return Err(fail(
            "the key that signed it is not the peer that was asked for",
        ));
    }
    if msg.operator_fingerprint != own_fingerprint {
        return Err(fail(
            "the peer saw a different operator fingerprint than this connection's (the relay rewrote it)",
        ));
    }
    let data = challenge_transcript(
        &peer_public_key,
        &msg.operator_fingerprint,
        &msg.nonce,
        &msg.session_id,
    );
    if !verify_with(&peer_public_key, &msg.signature, &data) {
        return Err(fail("the signature does not verify"));
    }
    Ok(VerifiedChallenge {
        peer_public_key,
        peer_fingerprint,
        nonce: msg.nonce.clone(),
        session_id: msg.session_id.clone(),
    })
}

/// Operator side: answer a verified challenge.
pub fn create_proof(
    key: &SigningKey,
    challenge: &VerifiedChallenge,
    username: &str,
) -> ReverseProofPayload {
    create_proof_with(key, challenge, username, &[])
}

/// [`create_proof`] that signs the statements in `features` (wsh #318; only those this crate knows: `gateway-lossless-close`). Send it only to a
/// peer that lists [`GATEWAY_LOSSLESS_SIGNED_FEATURE`].
pub fn create_proof_with(
    key: &SigningKey,
    challenge: &VerifiedChallenge,
    username: &str,
    features: &[&str],
) -> ReverseProofPayload {
    debug_assert!(features.iter().all(|f| SIGNABLE.contains(f)));
    let public_key = key.verifying_key().to_bytes();
    let signature = key
        .sign(&proof_transcript_with(
            &challenge.peer_public_key,
            &public_key,
            username,
            &challenge.nonce,
            &challenge.session_id,
            features,
        ))
        .to_bytes()
        .to_vec();
    ReverseProofPayload {
        // the relay stamps the peer it is for
        target_fingerprint: challenge.peer_fingerprint.clone(),
        public_key: public_key.to_vec(),
        username: username.to_string(),
        nonce: challenge.nonce.clone(),
        session_id: challenge.session_id.clone(),
        signature,
        from_fingerprint: None,
    }
}

/// An operator who proved it holds `public_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenOperator {
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub username: String,
    /// The statements the operator itself signed (wsh #318): empty for a v1 proof, `["gateway-lossless-close"]` for a v2 one. Whatever a relay did to
    /// `ReverseConnect.features`, this is what the operator said.
    pub signed_features: Vec<String>,
}

/// Peer side: check a `ReverseProof` against the challenge it issued. `None` when it does not verify.
pub fn verify_proof(msg: &ReverseProofPayload, issued: &IssuedChallenge) -> Option<ProvenOperator> {
    let public_key: [u8; 32] = msg.public_key.as_slice().try_into().ok()?;
    if msg.username.is_empty()
        || msg.username.len() > 64
        || msg.nonce != issued.nonce
        || msg.session_id != issued.session_id
    {
        return None;
    }
    // v1 (no statement signed), then v2 with the signable statement (wsh #318).
    let signed: &[&str] = [&[][..], SIGNABLE].into_iter().find(|features| {
        let data = proof_transcript_with(
            &issued.peer_public_key,
            &public_key,
            &msg.username,
            &issued.nonce,
            &issued.session_id,
            features,
        );
        verify_with(&public_key, &msg.signature, &data)
    })?;
    Some(ProvenOperator {
        public_key,
        fingerprint: fingerprint(&public_key),
        username: msg.username.clone(),
        signed_features: signed.iter().map(|f| f.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }
    fn fp(k: &SigningKey) -> String {
        fingerprint(&k.verifying_key().to_bytes())
    }

    #[test]
    fn transcript_layout_matches_the_js_implementation() {
        // challengeTranscript({ peerPublicKey: 0x01*32, operatorFingerprint: 'op', nonce: 0x02*32, sessionId: 'sid' })
        let t = challenge_transcript(&[1u8; 32], "op", &[2u8; 32], "sid");
        let mut want = b"wsh-reverse-challenge-v1\0".to_vec();
        want.extend([0, 0, 0, 32]);
        want.extend([1u8; 32]);
        want.extend([0, 0, 0, 2]);
        want.extend(b"op");
        want.extend([0, 0, 0, 32]);
        want.extend([2u8; 32]);
        want.extend([0, 0, 0, 3]);
        want.extend(b"sid");
        assert_eq!(t, want);
        let p = proof_transcript(&[1u8; 32], &[3u8; 32], "alice", &[2u8; 32], "sid");
        assert!(p.starts_with(b"wsh-operator-proof-v1\0"));
        assert_eq!(p.len(), 22 + 36 + 36 + 9 + 36 + 7);
    }

    #[test]
    fn transcripts_equal_the_bytes_the_js_implementation_produces() {
        // printed by src/operator-proof.mjs challengeTranscript / proofTranscript for the same inputs
        const CHALLENGE: &str = "7773682d726576657273652d6368616c6c656e67652d763100000000200101010101010101010101010101010101010101010101010101010101010101000000026f7000000020020202020202020202020202020202020202020202020202020202020202020200000003736964";
        const PROOF: &str = "7773682d6f70657261746f722d70726f6f662d76310000000020010101010101010101010101010101010101010101010101010101010101010100000020030303030303030303030303030303030303030303030303030303030303030300000005616c69636500000020020202020202020202020202020202020202020202020202020202020202020200000003736964";
        assert_eq!(
            hex::encode(challenge_transcript(&[1u8; 32], "op", &[2u8; 32], "sid")),
            CHALLENGE
        );
        assert_eq!(
            hex::encode(proof_transcript(
                &[1u8; 32], &[3u8; 32], "alice", &[2u8; 32], "sid"
            )),
            PROOF
        );
    }

    #[test]
    fn a_genuine_exchange_proves_the_operator() {
        let (peer, op) = (key(1), key(2));
        let (msg, issued) = create_challenge(&peer, &fp(&op), &fp(&op));
        let verified = verify_challenge(&msg, &fp(&peer)[..12], &fp(&op)).unwrap();
        let proof = create_proof(&op, &verified, "alice");
        let proven = verify_proof(&proof, &issued).unwrap();
        assert_eq!(proven.fingerprint, fp(&op));
        assert_eq!(proven.username, "alice");
    }

    #[test]
    fn a_v2_proof_signs_the_statement_and_v1_signs_none() {
        let (peer, op) = (key(1), key(2));
        let (msg, issued) = create_challenge(&peer, &fp(&op), &fp(&op));
        let verified = verify_challenge(&msg, &fp(&peer)[..12], &fp(&op)).unwrap();
        let v1 = verify_proof(&create_proof(&op, &verified, "alice"), &issued).unwrap();
        assert!(v1.signed_features.is_empty());
        let v2proof = create_proof_with(&op, &verified, "alice", &["gateway-lossless-close"]);
        let v2 = verify_proof(&v2proof, &issued).unwrap();
        assert_eq!(
            v2.signed_features,
            vec!["gateway-lossless-close".to_string()]
        );
        assert!(proof_transcript_with(
            &[1u8; 32],
            &[3u8; 32],
            "a",
            &[2u8; 32],
            "s",
            &["gateway-lossless-close"]
        )
        .starts_with(b"wsh-operator-proof-v2\0"));
    }

    #[test]
    fn the_v2_transcript_equals_the_bytes_the_js_implementation_produces() {
        // printed by src/operator-proof.mjs proofTranscript({ ..., features: ['gateway-lossless-close'] }) for the same inputs as the v1 vector
        const PROOF_V2: &str = "7773682d6f70657261746f722d70726f6f662d76320000000020010101010101010101010101010101010101010101010101010101010101010100000020030303030303030303030303030303030303030303030303030303030303030300000005616c6963650000002002020202020202020202020202020202020202020202020202020202020202020000000373696400000016676174657761792d6c6f73736c6573732d636c6f7365";
        assert_eq!(
            hex::encode(proof_transcript_with(
                &[1u8; 32],
                &[3u8; 32],
                "alice",
                &[2u8; 32],
                "sid",
                &["gateway-lossless-close"]
            )),
            PROOF_V2
        );
    }

    #[test]
    fn the_operator_refuses_a_challenge_for_another_peer_or_another_operator_fingerprint() {
        let (peer, op, other) = (key(1), key(2), key(3));
        let (msg, _) = create_challenge(&peer, &fp(&op), &fp(&op));
        assert!(
            verify_challenge(&msg, &fp(&other)[..12], &fp(&op)).is_err(),
            "not the peer asked for"
        );
        assert!(
            verify_challenge(&msg, &fp(&peer)[..12], &fp(&other)).is_err(),
            "relay rewrote the fingerprint"
        );
        let mut bad = msg.clone();
        bad.signature[0] ^= 1;
        assert!(verify_challenge(&bad, &fp(&peer)[..12], &fp(&op)).is_err());
    }

    #[test]
    fn a_proof_for_another_challenge_peer_key_or_swapped_key_is_refused() {
        let (peer, op, mallory) = (key(1), key(2), key(4));
        let (msg, issued) = create_challenge(&peer, &fp(&op), &fp(&op));
        let verified = verify_challenge(&msg, &fp(&peer)[..12], &fp(&op)).unwrap();
        let proof = create_proof(&op, &verified, "alice");
        // replayed against a later challenge of the same peer
        let (_, issued2) = create_challenge(&peer, &fp(&op), &fp(&op));
        assert!(verify_proof(&proof, &issued2).is_none());
        // a relay that swaps the public key cannot sign for the key it put there
        let mut swapped = proof.clone();
        swapped.public_key = mallory.verifying_key().to_bytes().to_vec();
        assert!(verify_proof(&swapped, &issued).is_none());
        // another username
        let mut renamed = proof.clone();
        renamed.username = "root".into();
        assert!(verify_proof(&renamed, &issued).is_none());
        assert!(verify_proof(&proof, &issued).is_some());
    }
}
