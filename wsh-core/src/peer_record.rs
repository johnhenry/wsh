//! Signed peer records for reverse-mode registration (libp2p RFC 0002/0003
//! signed-envelope pattern).
//!
//! A reverse peer (e.g. a browser tab) signs its own registration fields
//! with its Ed25519 identity key, so `ReversePeers` entries are verifiable
//! by an operator independent of trusting the relay server -- a relay
//! could otherwise misreport (or a malicious one forge) a peer's
//! capabilities/type/backend, or replay a stale record after a legitimate
//! update. Mirrors the "Signed peer records" section of
//! `@johnhenry/wsh`'s `src/auth.mjs`
//! (`buildPeerRecordTranscript`/`signPeerRecord`/`verifyPeerRecord`)
//! byte-for-byte.
//!
//! `PEER_RECORD_DOMAIN` is intentionally distinct from the auth-challenge
//! transcript's domain (`PROTOCOL_VERSION`, see
//! `wsh-server`'s `handshake::build_transcript` and `wsh-client`'s
//! `auth::build_transcript`) even though both are typically signed with
//! the same Ed25519 identity key -- a signature produced for one context
//! must never verify in the other.

use ring::signature::{self, Ed25519KeyPair};
use sha2::{Digest, Sha256};

/// Domain-separation prefix for peer-record transcripts.
const PEER_RECORD_DOMAIN: &[u8] = b"wsh-peer-record-v1\0";

/// Fields of a signed peer record, mirroring the JS `record` object passed
/// to `buildPeerRecordTranscript`/`signPeerRecord`/`verifyPeerRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub username: String,
    pub peer_type: String,
    pub shell_backend: String,
    pub capabilities: Vec<String>,
    pub supports_attach: bool,
    pub supports_replay: bool,
    pub supports_echo: bool,
    pub supports_term_sync: bool,
    /// The signing peer's own monotonic counter (in practice,
    /// current-time-millis); a verifier must reject a record whose `seq`
    /// doesn't exceed the last one it accepted for that fingerprint.
    pub seq: u64,
}

/// 4-byte big-endian length prefix, matching @johnhenry/wsh's
/// `lengthPrefixed()` and this crate's other transcript builders.
fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build the signed transcript for a peer record.
///
/// ```text
/// transcript = SHA-256(
///   "wsh-peer-record-v1\0" || lp(username) || lp(peerType) ||
///   lp(shellBackend) || lp(capabilities.join(',')) || flags(1 byte) ||
///   seq(8 BE bytes)
/// )
/// ```
///
/// `capabilities` is joined and length-prefixed as a single field rather
/// than iterated element-by-element, matching the JS implementation.
/// `flags` packs `supportsAttach | supportsReplay<<1 | supportsEcho<<2 |
/// supportsTermSync<<3`.
pub fn build_peer_record_transcript(record: &PeerRecord) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(PEER_RECORD_DOMAIN);
    hasher.update(length_prefixed(record.username.as_bytes()));
    hasher.update(length_prefixed(record.peer_type.as_bytes()));
    hasher.update(length_prefixed(record.shell_backend.as_bytes()));
    let capabilities_joined = record.capabilities.join(",");
    hasher.update(length_prefixed(capabilities_joined.as_bytes()));
    let flags: u8 = (record.supports_attach as u8)
        | ((record.supports_replay as u8) << 1)
        | ((record.supports_echo as u8) << 2)
        | ((record.supports_term_sync as u8) << 3);
    hasher.update([flags]);
    hasher.update(record.seq.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Sign a peer record with an Ed25519 identity key pair.
///
/// Returns the raw 64-byte Ed25519 signature.
pub fn sign_peer_record(key_pair: &Ed25519KeyPair, record: &PeerRecord) -> Vec<u8> {
    let transcript = build_peer_record_transcript(record);
    key_pair.sign(&transcript).as_ref().to_vec()
}

/// Verify a peer record's signature against a raw 32-byte Ed25519 public key.
pub fn verify_peer_record(public_key_raw: &[u8], signature: &[u8], record: &PeerRecord) -> bool {
    let transcript = build_peer_record_transcript(record);
    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_raw);
    public_key.verify(&transcript, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    fn gen_keypair() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate pkcs8");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse pkcs8");
        let public_key = key_pair.public_key().as_ref().to_vec();
        (key_pair, public_key)
    }

    fn base_record() -> PeerRecord {
        PeerRecord {
            username: "peer".to_string(),
            peer_type: "host".to_string(),
            shell_backend: "pty".to_string(),
            capabilities: vec!["exec".to_string()],
            supports_attach: false,
            supports_replay: false,
            supports_echo: false,
            supports_term_sync: false,
            seq: 1,
        }
    }

    #[test]
    fn transcript_is_32_bytes() {
        let transcript = build_peer_record_transcript(&base_record());
        assert_eq!(transcript.len(), 32);
    }

    #[test]
    fn transcript_is_deterministic_for_identical_records() {
        let record = base_record();
        let t1 = build_peer_record_transcript(&record);
        let t2 = build_peer_record_transcript(&record.clone());
        assert_eq!(t1, t2);
    }

    #[test]
    fn transcript_differs_when_any_field_changes() {
        let base = base_record();
        let baseline = build_peer_record_transcript(&base);

        let variants = vec![
            PeerRecord { username: "other".to_string(), ..base.clone() },
            PeerRecord { peer_type: "vm-guest".to_string(), ..base.clone() },
            PeerRecord { shell_backend: "virtual-shell".to_string(), ..base.clone() },
            PeerRecord { capabilities: vec!["shell".to_string()], ..base.clone() },
            PeerRecord { seq: 2, ..base.clone() },
            PeerRecord { supports_attach: true, ..base.clone() },
            PeerRecord { supports_replay: true, ..base.clone() },
            PeerRecord { supports_echo: true, ..base.clone() },
            PeerRecord { supports_term_sync: true, ..base.clone() },
        ];

        for variant in variants {
            let t = build_peer_record_transcript(&variant);
            assert_ne!(t, baseline, "expected a different transcript for {variant:?}");
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (key_pair, public_key) = gen_keypair();
        let record = PeerRecord {
            username: "browser-tab".to_string(),
            peer_type: "browser-shell".to_string(),
            shell_backend: "virtual-shell".to_string(),
            capabilities: vec!["shell".to_string(), "exec".to_string()],
            supports_attach: true,
            supports_replay: true,
            supports_echo: true,
            supports_term_sync: true,
            seq: 1_700_000_000_000,
        };

        let signature = sign_peer_record(&key_pair, &record);
        assert_eq!(signature.len(), 64);
        assert!(verify_peer_record(&public_key, &signature, &record));
    }

    #[test]
    fn verify_rejects_a_signature_for_a_different_record() {
        let (key_pair, public_key) = gen_keypair();
        let record = base_record();
        let signature = sign_peer_record(&key_pair, &record);

        let tampered = PeerRecord {
            capabilities: vec!["exec".to_string(), "shell".to_string()],
            ..record
        };
        assert!(!verify_peer_record(&public_key, &signature, &tampered));
    }

    #[test]
    fn verify_rejects_a_record_signed_by_a_different_key() {
        let (signer, _signer_public_key) = gen_keypair();
        let (_impostor, impostor_public_key) = gen_keypair();
        let record = base_record();
        let signature = sign_peer_record(&signer, &record);

        assert!(!verify_peer_record(&impostor_public_key, &signature, &record));
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let (key_pair, public_key) = gen_keypair();
        let record = base_record();
        let mut signature = sign_peer_record(&key_pair, &record);
        signature[0] ^= 0xff;

        assert!(!verify_peer_record(&public_key, &signature, &record));
    }

    /// A peer-record signature must never verify as an auth-challenge
    /// signature, and vice versa, even when both are produced by the same
    /// identity key over fields that would otherwise coincide. wsh-core
    /// doesn't own the auth-challenge transcript builder (that trio lives
    /// per-crate in `wsh-server::handshake` / `wsh-client::auth`, mirroring
    /// `@johnhenry/wsh`'s `buildTranscript`/`signChallenge`/
    /// `verifyChallenge`), so this test reconstructs that transcript's
    /// exact byte layout minimally, inline, purely to prove the two
    /// domains never cross. See `test/auth.test.mjs`'s "a peer-record
    /// signature does not verify as an auth-challenge signature and vice
    /// versa (domain separation)" test in `@johnhenry/wsh`, which this
    /// mirrors.
    #[test]
    fn domain_separation_from_auth_challenge_transcript() {
        let (key_pair, public_key) = gen_keypair();
        let record = PeerRecord {
            username: "u".to_string(),
            ..base_record()
        };
        let record_signature = sign_peer_record(&key_pair, &record);

        // SHA-256(PROTOCOL_VERSION || "\0" || lp(username) || lp(session_id) || nonce)
        let mut hasher = Sha256::new();
        hasher.update(crate::messages::PROTOCOL_VERSION.as_bytes());
        hasher.update(b"\0");
        hasher.update(length_prefixed(record.username.as_bytes()));
        hasher.update(length_prefixed(b"session-1"));
        hasher.update(b"0123456789abcdef0123456789abcdef"); // 32-ish byte "nonce"
        let challenge_transcript = hasher.finalize().to_vec();
        let challenge_signature = key_pair.sign(&challenge_transcript).as_ref().to_vec();

        // A peer-record signature must not verify as an auth-challenge signature...
        let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key);
        assert!(verifier.verify(&challenge_transcript, &record_signature).is_err());
        // ...and vice versa: an auth-challenge signature must not verify as a peer record.
        assert!(!verify_peer_record(&public_key, &challenge_signature, &record));
    }
}

