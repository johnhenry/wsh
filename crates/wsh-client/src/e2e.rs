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

use ring::hkdf;

use wsh_core::error::{WshError, WshResult};

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
