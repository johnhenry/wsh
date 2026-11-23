//! Password hashes for `[auth.password_hashes]`.
//!
//! A stored hash is an Argon2id PHC string (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`)
//! with a random per-user salt, made by `wsh-server --hash-password`. Verification
//! compares in constant time (the `argon2` crate compares the derived output with
//! `subtle`), and an unknown user costs the same work as a wrong password so neither
//! timing nor the failure message says which usernames exist.
//!
//! The old format, `sha256:<hex>` (one unsalted SHA-256 of the password), is refused
//! unless `[auth] allow_legacy_sha256 = true` -- see [`StoredHash::parse`]. A leaked
//! file of those can be brute-forced and looked up in precomputed tables at
//! billions of guesses a second; it is accepted only as a stop-gap for one release.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

/// A parsed `password_hashes` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredHash {
    /// `$argon2id$...` PHC string.
    Argon2id(String),
    /// `sha256:<hex>`, unsalted. Only verifiable when legacy support is on.
    LegacySha256([u8; 32]),
}

/// Why a stored value cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashProblem {
    /// A `sha256:` entry and `allow_legacy_sha256` is off.
    LegacyRefused,
    /// Neither an Argon2id PHC string nor `sha256:<64 hex digits>`.
    Unrecognised(String),
}

impl std::fmt::Display for HashProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyRefused => write!(
                f,
                "unsalted sha256 hashes are no longer accepted: replace it with the output of \
                 `wsh-server --hash-password`, or set `allow_legacy_sha256 = true` under [auth] \
                 to keep it working for now"
            ),
            Self::Unrecognised(why) => write!(f, "not a usable password hash ({why})"),
        }
    }
}

impl StoredHash {
    /// Parse one configured value.
    pub fn parse(value: &str, allow_legacy_sha256: bool) -> Result<Self, HashProblem> {
        if let Some(hex_digest) = value.strip_prefix("sha256:") {
            if !allow_legacy_sha256 {
                return Err(HashProblem::LegacyRefused);
            }
            let bytes = hex::decode(hex_digest)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| HashProblem::Unrecognised("sha256: needs 64 hex digits".into()))?;
            return Ok(Self::LegacySha256(bytes));
        }
        let parsed = PasswordHash::new(value)
            .map_err(|e| HashProblem::Unrecognised(format!("not a PHC string: {e}")))?;
        if parsed.algorithm.as_str() != Algorithm::Argon2id.ident().as_str() {
            return Err(HashProblem::Unrecognised(format!(
                "algorithm '{}' is not accepted, only argon2id",
                parsed.algorithm
            )));
        }
        Ok(Self::Argon2id(value.to_string()))
    }

    /// Does `password` match? Constant-time in the comparison itself.
    pub fn verify(&self, password: &str) -> bool {
        match self {
            Self::Argon2id(phc) => PasswordHash::new(phc)
                .map(|parsed| {
                    Argon2::default()
                        .verify_password(password.as_bytes(), &parsed)
                        .is_ok()
                })
                .unwrap_or(false),
            Self::LegacySha256(expected) => {
                let computed: [u8; 32] = Sha256::digest(password.as_bytes()).into();
                computed.ct_eq(expected).into()
            }
        }
    }
}

/// Hash `password` with Argon2id (the crate's default parameters, which are the
/// OWASP minimum: 19 MiB, 2 passes, 1 lane) and a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verify a login attempt for `username`.
///
/// `stored` is the user's configured value, if there is one. A missing, unusable or
/// refused entry still does a full hash, against a fixed decoy, and fails: the answer
/// and the time taken are the same as for a wrong password.
pub fn verify_login(password: &str, stored: Option<&StoredHash>) -> bool {
    match stored {
        Some(hash) => hash.verify(password),
        None => {
            static DECOY: OnceLock<StoredHash> = OnceLock::new();
            let decoy = DECOY.get_or_init(|| {
                StoredHash::Argon2id(
                    hash_password("wsh decoy: nobody's password")
                        .expect("argon2 with default parameters cannot fail"),
                )
            });
            let _ = decoy.verify(password);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_is_a_salted_argon2id_phc_string_that_verifies() {
        let a = hash_password("correct horse").unwrap();
        let b = hash_password("correct horse").unwrap();
        assert!(a.starts_with("$argon2id$v=19$"), "{a}");
        assert_ne!(a, b, "same password, different salt, different hash");
        let stored = StoredHash::parse(&a, false).unwrap();
        assert!(stored.verify("correct horse"));
        assert!(!stored.verify("correct horse "));
        assert!(!stored.verify(""));
    }

    #[test]
    fn only_argon2id_is_accepted_as_a_phc_string() {
        let id = hash_password("pw").unwrap();
        let as_argon2i = id.replacen("$argon2id$", "$argon2i$", 1);
        assert!(matches!(
            StoredHash::parse(&as_argon2i, false),
            Err(HashProblem::Unrecognised(_))
        ));
        assert!(matches!(
            StoredHash::parse("plaintext-password", false),
            Err(HashProblem::Unrecognised(_))
        ));
        assert!(matches!(
            StoredHash::parse(
                "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
                false
            ),
            Err(HashProblem::Unrecognised(_))
        ));
    }

    // sha256("password"), the kind of value an old config holds.
    const SHA256_PASSWORD: &str =
        "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

    #[test]
    fn an_unsalted_sha256_entry_is_refused_by_default() {
        assert_eq!(
            StoredHash::parse(SHA256_PASSWORD, false),
            Err(HashProblem::LegacyRefused)
        );
        let msg = HashProblem::LegacyRefused.to_string();
        assert!(msg.contains("--hash-password") && msg.contains("allow_legacy_sha256"));
    }

    #[test]
    fn an_unsalted_sha256_entry_works_only_when_legacy_is_switched_on() {
        let stored = StoredHash::parse(SHA256_PASSWORD, true).unwrap();
        assert!(stored.verify("password"));
        assert!(!stored.verify("Password"));
        assert!(matches!(
            StoredHash::parse("sha256:abc", true),
            Err(HashProblem::Unrecognised(_))
        ));
    }

    #[test]
    fn an_unknown_user_fails_and_does_the_same_work_as_a_wrong_password() {
        let phc = hash_password("pw").unwrap();
        let stored = StoredHash::parse(&phc, false).unwrap();
        assert!(!verify_login("pw", None), "no entry never logs in");
        assert!(verify_login("pw", Some(&stored)));

        // Same order of cost: both run one Argon2id derivation. (A generous bound --
        // this guards against the unknown-user branch returning immediately, which
        // would let an attacker tell which usernames exist.)
        let time = |f: &dyn Fn() -> bool| {
            let start = std::time::Instant::now();
            let _ = f();
            start.elapsed()
        };
        let _ = verify_login("warm", None);
        let known = time(&|| verify_login("wrong", Some(&stored)));
        let unknown = time(&|| verify_login("wrong", None));
        assert!(
            unknown * 4 > known,
            "unknown user answered in {unknown:?}, a wrong password took {known:?}"
        );
    }
}
