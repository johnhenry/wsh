//! Shortest-unique-prefix fingerprints for Ed25519 public keys.
//!
//! Like git's short hashes: fingerprint = SHA-256(raw_pubkey), displayed
//! as the shortest hex prefix that's unique within a given context.

use sha2::{Digest, Sha256};

/// Compute the full hex-encoded SHA-256 fingerprint of a raw public key.
pub fn fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hex::encode(hash)
}

/// Find the shortest unique prefix for a fingerprint within a set.
///
/// Returns a prefix of at least `min_len` characters that uniquely identifies
/// `fp` among all `fingerprints`.
pub fn short_fingerprint(fp: &str, fingerprints: &[&str], min_len: usize) -> String {
    let min_len = min_len.max(4); // never shorter than 4 chars
    let others: Vec<&str> = fingerprints.iter().filter(|&&f| f != fp).copied().collect();

    for len in min_len..=fp.len() {
        let prefix = &fp[..len];
        if !others.iter().any(|f| f.starts_with(prefix)) {
            return prefix.to_string();
        }
    }
    fp.to_string()
}

/// Resolve a short prefix to a full fingerprint from a list.
///
/// Returns `None` if no match, `Err` if ambiguous, `Ok` if unique match.
pub fn resolve_prefix<'a>(
    prefix: &str,
    fingerprints: &[&'a str],
) -> Result<Option<&'a str>, Vec<&'a str>> {
    let matches: Vec<&str> = fingerprints
        .iter()
        .filter(|&&f| f.starts_with(prefix))
        .copied()
        .collect();

    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches[0])),
        _ => Err(matches),
    }
}

/// Build a fingerprint index for O(1)-ish prefix lookup.
#[derive(Debug, Default)]
pub struct FingerprintIndex {
    entries: Vec<(String, String)>, // (fingerprint, associated_id)
}

impl FingerprintIndex {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a fingerprint with an associated identifier (e.g. username).
    pub fn insert(&mut self, fingerprint: String, id: String) {
        self.entries.push((fingerprint, id));
    }

    /// Remove entries matching a fingerprint.
    pub fn remove(&mut self, fingerprint: &str) {
        self.entries.retain(|(fp, _)| fp != fingerprint);
    }

    /// Resolve a prefix to a (fingerprint, id) pair.
    pub fn resolve(&self, prefix: &str) -> Result<Option<(&str, &str)>, Vec<(&str, &str)>> {
        let matches: Vec<(&str, &str)> = self
            .entries
            .iter()
            .filter(|(fp, _)| fp.starts_with(prefix))
            .map(|(fp, id)| (fp.as_str(), id.as_str()))
            .collect();

        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches[0])),
            _ => Err(matches),
        }
    }

    /// Get the shortest unique prefix for each entry.
    pub fn short_prefixes(&self, min_len: usize) -> Vec<(&str, String)> {
        let fps: Vec<&str> = self.entries.iter().map(|(fp, _)| fp.as_str()).collect();
        self.entries
            .iter()
            .map(|(fp, _)| (fp.as_str(), short_fingerprint(fp, &fps, min_len)))
            .collect()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries as (fingerprint, id) pairs.
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_hex_sha256() {
        let key = b"test-key-32-bytes-padded-to-32b!";
        let fp = fingerprint(key);
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn short_fingerprint_uniqueness() {
        let fps = ["a3f8c2d1e4", "a3f8d5b2c3", "b1c2d3e4f5"];
        let short = short_fingerprint("a3f8c2d1e4", &fps, 4);
        assert_eq!(short, "a3f8c"); // 5 chars to distinguish from a3f8d...
    }

    #[test]
    fn short_fingerprint_min_length() {
        let fps = ["a3f8c2", "b1c2d3"];
        let short = short_fingerprint("a3f8c2", &fps, 4);
        assert_eq!(short, "a3f8"); // min length 4
    }

    #[test]
    fn resolve_prefix_unique() {
        let fps = ["a3f8c2d1e4", "b1c2d3e4f5"];
        assert_eq!(resolve_prefix("a3", &fps), Ok(Some("a3f8c2d1e4")));
    }

    #[test]
    fn resolve_prefix_ambiguous() {
        let fps = ["a3f8c2d1e4", "a3f8d5b2c3"];
        assert!(resolve_prefix("a3f8", &fps).is_err());
    }

    #[test]
    fn resolve_prefix_not_found() {
        let fps = ["a3f8c2d1e4"];
        assert_eq!(resolve_prefix("zz", &fps), Ok(None));
    }

    #[test]
    fn fingerprint_index_operations() {
        let mut idx = FingerprintIndex::new();
        idx.insert("a3f8c2d1e4".into(), "alice".into());
        idx.insert("b1c2d3e4f5".into(), "bob".into());

        assert_eq!(idx.len(), 2);
        assert_eq!(idx.resolve("a3").unwrap(), Some(("a3f8c2d1e4", "alice")));

        idx.remove("a3f8c2d1e4");
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.resolve("a3").unwrap(), None);
    }
}
