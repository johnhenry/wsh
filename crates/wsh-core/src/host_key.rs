//! Host-key proof (wsh #59, #117, #145): the host proves it holds the Ed25519 key behind
//! `ServerHello.host_fingerprint`, over this connection, before any credential is sent.
//!
//! Byte-compatible with `src/host-key.mjs`. The wire shape rides in the negotiable `features`
//! string lists, so released peers that do not know the strings ignore them:
//!
//! - client -> server, `Hello.features`: `host-key-nonce:<hex>` (fresh, 16 bytes);
//! - server -> client, `ServerHello.features`: `host-key:<hex>` (the raw 32-byte public key)
//!   and `host-key-sig:<hex>` (an Ed25519 signature over [`proof_message`]);
//!   `ServerHello.host_fingerprint` is the fingerprint of that key.
//!
//! The proof message is `"wsh-host-key-proof-v1" 0x00 session_id 0x00 client_nonce 0x00 username`
//! (nonce as lower-case hex text). The fresh nonce makes a proof unreplayable; the session id
//! binds it to this `ServerHello`.
//!
//! A bare `host_fingerprint` with no `host-key`/`host-key-sig` is NOT a proof: nothing stops
//! anyone from repeating a fingerprint they saw. [`verify_advert`] treats such a host as having
//! no host key, and refuses a host that advertises a key it cannot prove.

use crate::identity::fingerprint;
use crate::{WshError, WshResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

pub const HOST_KEY_NONCE_PREFIX: &str = "host-key-nonce:";
pub const HOST_KEY_PREFIX: &str = "host-key:";
pub const HOST_KEY_SIG_PREFIX: &str = "host-key-sig:";
const PROOF_TAG: &str = "wsh-host-key-proof-v1";

/// A host key that proved possession over this connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenHostKey {
    /// The raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// Hex SHA-256 of `public_key` -- what `known_hosts` records.
    pub fingerprint: String,
}

/// A fresh client nonce, hex (16 random bytes).
pub fn new_nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// The bytes the host signs and the client verifies.
pub fn proof_message(session_id: &str, client_nonce: &str, username: &str) -> Vec<u8> {
    format!("{PROOF_TAG}\0{session_id}\0{client_nonce}\0{username}").into_bytes()
}

/// Pull the client nonce out of `Hello.features` (server side). `None` when absent or malformed.
pub fn find_client_nonce(features: &[String]) -> Option<String> {
    features
        .iter()
        .filter_map(|f| f.strip_prefix(HOST_KEY_NONCE_PREFIX))
        .find(|h| (32..=128).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|h| h.to_ascii_lowercase())
}

/// What `ServerHello.features` advertised. A malformed value counts as absent (so the caller
/// refuses it as an incomplete proof), as in the JS client; the last of each prefix wins.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostKeyAdvert {
    pub key: Option<Vec<u8>>,
    pub sig: Option<Vec<u8>>,
}

pub fn find_advert(features: &[String]) -> Option<HostKeyAdvert> {
    let mut advert = HostKeyAdvert::default();
    for f in features {
        if let Some(h) = f.strip_prefix(HOST_KEY_SIG_PREFIX) {
            advert.sig = hex::decode(h).ok();
        } else if let Some(h) = f.strip_prefix(HOST_KEY_PREFIX) {
            advert.key = hex::decode(h).ok();
        }
    }
    (advert.key.is_some() || advert.sig.is_some()).then_some(advert)
}

/// The `ServerHello` feature strings that prove `key` over this connection (server side).
pub fn advert_features(
    key: &SigningKey,
    session_id: &str,
    client_nonce: &str,
    username: &str,
) -> [String; 2] {
    let sig = key.sign(&proof_message(session_id, client_nonce, username));
    [
        format!(
            "{HOST_KEY_PREFIX}{}",
            hex::encode(key.verifying_key().to_bytes())
        ),
        format!("{HOST_KEY_SIG_PREFIX}{}", hex::encode(sig.to_bytes())),
    ]
}

/// Check what a `ServerHello` says about the host key.
///
/// - no `host-key`/`host-key-sig` feature -> `Ok(None)`: the host has no (provable) host key;
/// - an advert that is malformed, unsigned, signed over another connection, or whose
///   `host_fingerprint` is not the advertised key's -> an error: the host claims a key it
///   cannot prove, which is never the same as having none;
/// - otherwise `Ok(Some(key))`.
pub fn verify_advert(
    features: &[String],
    host_fingerprint: Option<&str>,
    session_id: &str,
    client_nonce: &str,
    username: &str,
) -> WshResult<Option<ProvenHostKey>> {
    let Some(advert) = find_advert(features) else {
        return Ok(None);
    };
    let invalid = |why: &str| WshError::AuthFailed(format!("HOST KEY INVALID: {why}"));
    let (Some(key), Some(sig)) = (advert.key, advert.sig) else {
        return Err(invalid(
            "server advertised a malformed host key or no proof of possession",
        ));
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| invalid("server advertised a malformed host key or no proof of possession"))?;
    let vk = VerifyingKey::from_bytes(&key)
        .map_err(|_| invalid("server advertised a malformed host key or no proof of possession"))?;
    let sig = Signature::from_slice(&sig)
        .map_err(|_| invalid("server advertised a malformed host key or no proof of possession"))?;
    vk.verify(&proof_message(session_id, client_nonce, username), &sig)
        .map_err(|_| invalid("host key proof does not verify (not signed over this connection)"))?;
    let fp = fingerprint(&key);
    if let Some(claimed) = host_fingerprint.filter(|f| !f.is_empty()) {
        if claimed != fp {
            return Err(invalid(
                "ServerHello.host_fingerprint does not match the advertised host key",
            ));
        }
    }
    Ok(Some(ProvenHostKey {
        public_key: key,
        fingerprint: fp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn proof_message_layout_matches_the_js_client() {
        // hostKeyProofMessage({ sessionId: 'sid', clientNonce: 'ab', username: 'alice' })
        assert_eq!(
            proof_message("sid", "ab", "alice"),
            b"wsh-host-key-proof-v1\0sid\0ab\0alice".to_vec()
        );
    }

    #[test]
    fn nonce_is_16_random_bytes_of_hex() {
        let a = new_nonce();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, new_nonce());
    }

    #[test]
    fn a_genuine_proof_verifies_and_yields_the_fingerprint() {
        let k = key(7);
        let nonce = new_nonce();
        let features = advert_features(&k, "sid-1", &nonce, "alice").to_vec();
        let proven = verify_advert(&features, None, "sid-1", &nonce, "alice")
            .unwrap()
            .unwrap();
        assert_eq!(proven.public_key, k.verifying_key().to_bytes());
        assert_eq!(proven.fingerprint, fingerprint(&proven.public_key));
        // with a matching host_fingerprint too
        assert!(verify_advert(
            &features,
            Some(&proven.fingerprint),
            "sid-1",
            &nonce,
            "alice"
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn no_advert_is_no_host_key_not_an_error() {
        assert_eq!(
            verify_advert(&["mcp".into()], Some("abcd"), "s", "n", "u").unwrap(),
            None,
            "a bare host_fingerprint proves nothing"
        );
    }

    #[test]
    fn a_proof_replayed_from_another_session_nonce_or_user_is_refused() {
        let k = key(7);
        let nonce = new_nonce();
        let features = advert_features(&k, "sid-1", &nonce, "alice").to_vec();
        assert!(verify_advert(&features, None, "sid-2", &nonce, "alice").is_err());
        assert!(verify_advert(&features, None, "sid-1", &new_nonce(), "alice").is_err());
        assert!(verify_advert(&features, None, "sid-1", &nonce, "mallory").is_err());
    }

    #[test]
    fn a_key_without_a_signature_or_the_wrong_fingerprint_is_refused() {
        let k = key(7);
        let nonce = new_nonce();
        let mut features = advert_features(&k, "s", &nonce, "u").to_vec();
        assert!(verify_advert(&features[..1], None, "s", &nonce, "u").is_err());
        assert!(
            verify_advert(&features, Some(&fingerprint(&[9u8; 32])), "s", &nonce, "u").is_err()
        );
        // someone else's key with this host's signature
        features[0] = format!(
            "{HOST_KEY_PREFIX}{}",
            hex::encode(key(8).verifying_key().to_bytes())
        );
        assert!(verify_advert(&features, None, "s", &nonce, "u").is_err());
        // garbage
        assert!(verify_advert(
            &[
                format!("{HOST_KEY_PREFIX}zz"),
                format!("{HOST_KEY_SIG_PREFIX}00")
            ],
            None,
            "s",
            &nonce,
            "u"
        )
        .is_err());
    }

    #[test]
    fn client_nonce_parsing_matches_the_js_host() {
        let n = new_nonce();
        assert_eq!(
            find_client_nonce(&[format!("{HOST_KEY_NONCE_PREFIX}{}", n.to_uppercase())]),
            Some(n)
        );
        assert_eq!(
            find_client_nonce(&[format!("{HOST_KEY_NONCE_PREFIX}abcd")]),
            None
        );
        assert_eq!(find_client_nonce(&["mcp".into()]), None);
    }
}
