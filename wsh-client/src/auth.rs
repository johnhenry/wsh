//! Ed25519 authentication for the wsh protocol.
//!
//! Provides keypair generation, challenge signing, and verification.
//! The challenge transcript matches the JS implementation:
//!   `SHA-256("wsh-v1\0" || session_id || nonce)`

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wsh_core::{WshError, WshResult, PROTOCOL_VERSION};

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Build the challenge transcript that both client and server compute.
///
/// Format: `SHA-256("wsh-v1\0" || session_id || nonce)`
///
/// The null byte separator matches the JS implementation exactly.
fn build_transcript(session_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(PROTOCOL_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(session_id.as_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

/// Sign a server challenge using the client's signing key.
///
/// Returns the raw Ed25519 signature bytes (64 bytes).
pub fn sign_challenge(signing_key: &SigningKey, session_id: &str, nonce: &[u8]) -> Vec<u8> {
    let transcript = build_transcript(session_id, nonce);
    let signature = signing_key.sign(&transcript);
    signature.to_bytes().to_vec()
}

/// Verify a challenge signature against a public key.
pub fn verify_challenge(
    verifying_key: &VerifyingKey,
    signature: &[u8],
    session_id: &str,
    nonce: &[u8],
) -> bool {
    let transcript = build_transcript(session_id, nonce);

    let sig = match ed25519_dalek::Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(&transcript, &sig).is_ok()
}

/// Extract the raw 32-byte public key bytes from a `VerifyingKey`.
pub fn public_key_bytes(vk: &VerifyingKey) -> Vec<u8> {
    vk.to_bytes().to_vec()
}

/// Reconstruct a `VerifyingKey` from raw 32-byte public key bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> WshResult<VerifyingKey> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        WshError::AuthFailed("invalid public key length (expected 32 bytes)".into())
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| WshError::AuthFailed(format!("invalid public key: {e}")))
}

/// Reconstruct a `SigningKey` from raw 32-byte secret key bytes.
pub fn signing_key_from_bytes(bytes: &[u8]) -> WshResult<SigningKey> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        WshError::AuthFailed("invalid secret key length (expected 32 bytes)".into())
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let (sk, vk) = generate_keypair();
        assert_eq!(sk.verifying_key(), vk);
    }

    #[test]
    fn sign_and_verify() {
        let (sk, vk) = generate_keypair();
        let session_id = "test-session-123";
        let nonce = b"random-nonce-bytes";

        let sig = sign_challenge(&sk, session_id, nonce);
        assert_eq!(sig.len(), 64);
        assert!(verify_challenge(&vk, &sig, session_id, nonce));
    }

    #[test]
    fn wrong_session_id_fails() {
        let (sk, vk) = generate_keypair();
        let nonce = b"nonce";

        let sig = sign_challenge(&sk, "session-a", nonce);
        assert!(!verify_challenge(&vk, &sig, "session-b", nonce));
    }

    #[test]
    fn wrong_nonce_fails() {
        let (sk, vk) = generate_keypair();
        let session_id = "session";

        let sig = sign_challenge(&sk, session_id, b"nonce-a");
        assert!(!verify_challenge(&vk, &sig, session_id, b"nonce-b"));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _vk) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let session_id = "session";
        let nonce = b"nonce";

        let sig = sign_challenge(&sk, session_id, nonce);
        assert!(!verify_challenge(&vk2, &sig, session_id, nonce));
    }

    #[test]
    fn public_key_round_trip() {
        let (_sk, vk) = generate_keypair();
        let bytes = public_key_bytes(&vk);
        let vk2 = verifying_key_from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn transcript_deterministic() {
        let t1 = build_transcript("sess", b"nonce");
        let t2 = build_transcript("sess", b"nonce");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32); // SHA-256 output
    }
}
