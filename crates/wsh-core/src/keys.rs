//! Parse `authorized_keys` files (SSH format).
//!
//! Supports reading Ed25519 public keys from both `~/.wsh/authorized_keys`
//! and `~/.ssh/authorized_keys`, with wsh taking priority.

use crate::error::WshResult;
use crate::identity;
use std::path::Path;

/// A parsed authorized key entry.
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    /// Key type (e.g., "ssh-ed25519").
    pub key_type: String,
    /// Base64-encoded key data.
    pub key_data: String,
    /// Raw decoded key bytes (SSH wire format).
    pub raw: Vec<u8>,
    /// Optional comment (usually user@host).
    pub comment: String,
    /// SHA-256 fingerprint (hex).
    pub fingerprint: String,
    /// Optional restrictions/options from the authorized_keys line.
    pub options: Option<String>,
}

/// Parse an authorized_keys file, returning all valid Ed25519 entries.
pub fn parse_authorized_keys(content: &str) -> Vec<AuthorizedKey> {
    content
        .lines()
        .filter_map(|line| parse_authorized_key_line(line.trim()))
        .collect()
}

/// Parse a single authorized_keys line.
fn parse_authorized_key_line(line: &str) -> Option<AuthorizedKey> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    // Check if first field is options (not a key type)
    let (options, key_type, key_data, comment) = if parts[0].starts_with("ssh-") {
        (
            None,
            parts[0].to_string(),
            parts[1].to_string(),
            parts.get(2).unwrap_or(&"").to_string(),
        )
    } else if parts.len() >= 3 {
        // First field is options, re-parse from after options
        let after_opts: Vec<&str> = line[parts[0].len()..].trim().splitn(3, ' ').collect();
        if after_opts.len() < 2 {
            return None;
        }
        (
            Some(parts[0].to_string()),
            after_opts[0].to_string(),
            after_opts[1].to_string(),
            after_opts.get(2).unwrap_or(&"").to_string(),
        )
    } else {
        return None;
    };

    // Only support ed25519
    if key_type != "ssh-ed25519" {
        return None;
    }

    // Decode base64
    let raw = match base64_decode(&key_data) {
        Some(r) => r,
        None => return None,
    };

    // Extract the raw 32-byte key from SSH wire format to compute fingerprint
    let raw_key = extract_raw_ed25519(&raw)?;
    let fingerprint = identity::fingerprint(&raw_key);

    Some(AuthorizedKey {
        key_type,
        key_data,
        raw,
        comment,
        fingerprint,
        options,
    })
}

/// Extract the raw 32-byte Ed25519 public key from SSH wire format.
///
/// SSH wire format: `[4-byte len]["ssh-ed25519"][4-byte len][32-byte key]`
fn extract_raw_ed25519(wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < 4 {
        return None;
    }
    let type_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    let key_offset = 4 + type_len;
    if wire.len() < key_offset + 4 {
        return None;
    }
    let key_len = u32::from_be_bytes([
        wire[key_offset],
        wire[key_offset + 1],
        wire[key_offset + 2],
        wire[key_offset + 3],
    ]) as usize;
    let data_offset = key_offset + 4;
    if wire.len() < data_offset + key_len {
        return None;
    }
    Some(wire[data_offset..data_offset + key_len].to_vec())
}

/// Load authorized keys from wsh and ssh directories, with wsh taking priority.
pub fn load_authorized_keys(home: &Path) -> WshResult<Vec<AuthorizedKey>> {
    let mut keys = Vec::new();
    let mut seen_fingerprints = std::collections::HashSet::new();

    // Try ~/.wsh/authorized_keys first (priority)
    let wsh_path = home.join(".wsh").join("authorized_keys");
    if wsh_path.exists() {
        let content = std::fs::read_to_string(&wsh_path)?;
        for key in parse_authorized_keys(&content) {
            seen_fingerprints.insert(key.fingerprint.clone());
            keys.push(key);
        }
    }

    // Then ~/.ssh/authorized_keys (fallback, skip duplicates)
    let ssh_path = home.join(".ssh").join("authorized_keys");
    if ssh_path.exists() {
        let content = std::fs::read_to_string(&ssh_path)?;
        for key in parse_authorized_keys(&content) {
            if !seen_fingerprints.contains(&key.fingerprint) {
                seen_fingerprints.insert(key.fingerprint.clone());
                keys.push(key);
            }
        }
    }

    Ok(keys)
}

/// Check if a raw public key is authorized.
pub fn is_key_authorized(public_key_raw: &[u8], authorized: &[AuthorizedKey]) -> bool {
    let fp = identity::fingerprint(public_key_raw);
    authorized.iter().any(|k| k.fingerprint == fp)
}

// ── Base64 helpers ────────────────────────────────────────────────────

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Standard base64 alphabet
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let bytes: Vec<u8> = input.bytes().collect();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = lookup[bytes[i] as usize];
        let b = lookup[bytes[i + 1] as usize];
        let c = lookup[bytes[i + 2] as usize];
        let d = lookup[bytes[i + 3] as usize];
        if a == 255 || b == 255 || c == 255 || d == 255 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
        output.push((c << 6) | d);
        i += 4;
    }

    let remaining = bytes.len() - i;
    if remaining == 2 {
        let a = lookup[bytes[i] as usize];
        let b = lookup[bytes[i + 1] as usize];
        if a == 255 || b == 255 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
    } else if remaining == 3 {
        let a = lookup[bytes[i] as usize];
        let b = lookup[bytes[i + 1] as usize];
        let c = lookup[bytes[i + 2] as usize];
        if a == 255 || b == 255 || c == 255 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
    }

    Some(output)
}

/// Base64-encode arbitrary bytes (standard alphabet, `=` padding).
///
/// Public (unlike `base64_decode` above) so callers outside this crate --
/// currently `wsh-server`'s `AuthorizedKeyAdd` handler (wsh #59) -- can
/// format a raw public key as an `authorized_keys` line without a base64
/// crate dependency, mirroring the equivalent private helper in
/// `wsh-client`'s `keystore.rs` (kept separate there since that one also
/// needs `base64_decode`, unlike this crate's already-public parsing path).
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        result.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        result.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        result.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push('=');
        result.push('=');
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        result.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        result.push('=');
    }

    result
}

/// Encode a 32-byte Ed25519 public key into SSH wire format:
/// `[4-byte len]["ssh-ed25519"][4-byte len][32-byte key]`.
pub fn encode_ssh_ed25519_wire(public_key: &[u8; 32]) -> Vec<u8> {
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    wire.extend_from_slice(public_key);
    wire
}

/// Format a raw 32-byte Ed25519 public key as an `authorized_keys` line:
/// `ssh-ed25519 <base64> [comment]`.
pub fn format_authorized_key_line(raw_key: &[u8; 32], comment: &str) -> String {
    let wire = encode_ssh_ed25519_wire(raw_key);
    let b64 = base64_encode(&wire);
    if comment.is_empty() {
        format!("ssh-ed25519 {b64}")
    } else {
        format!("ssh-ed25519 {b64} {comment}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid SSH ed25519 wire format: [4B len]["ssh-ed25519"][4B len][32B key]
    const TEST_KEY_B64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    #[test]
    fn parse_simple_ed25519() {
        let line = format!("ssh-ed25519 {} user@host", TEST_KEY_B64);
        let keys = parse_authorized_keys(&line);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].comment, "user@host");
        assert!(!keys[0].fingerprint.is_empty());
    }

    #[test]
    fn skip_comments_and_empty() {
        let content = format!("# comment\n\nssh-ed25519 {} test\n", TEST_KEY_B64);
        let keys = parse_authorized_keys(&content);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn skip_non_ed25519() {
        let content = "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host";
        let keys = parse_authorized_keys(content);
        assert_eq!(keys.len(), 0);
    }

    // ── base64_encode / encode_ssh_ed25519_wire / format_authorized_key_line ──
    // (wsh #59: added for the server-side AuthorizedKeyAdd handler, which
    // needs to format a raw public key as an authorized_keys line without
    // pulling in a base64 crate dependency.)

    #[test]
    fn base64_encode_round_trips_through_base64_decode() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        ] {
            let encoded = base64_encode(data);
            let decoded = base64_decode(&encoded).expect("valid base64 must decode");
            assert_eq!(decoded, data, "round trip failed for {data:?}");
        }
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encode_ssh_ed25519_wire_matches_expected_layout() {
        let key = [7u8; 32];
        let wire = encode_ssh_ed25519_wire(&key);
        // [4B len=11]["ssh-ed25519"][4B len=32][32B key]
        assert_eq!(&wire[0..4], &11u32.to_be_bytes());
        assert_eq!(&wire[4..15], b"ssh-ed25519");
        assert_eq!(&wire[15..19], &32u32.to_be_bytes());
        assert_eq!(&wire[19..51], &key[..]);
        assert_eq!(wire.len(), 51);
    }

    #[test]
    fn format_authorized_key_line_round_trips_through_parse_authorized_keys() {
        let key = [9u8; 32];
        let line = format_authorized_key_line(&key, "alice@laptop");
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" alice@laptop"));

        let parsed = parse_authorized_keys(&line);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].comment, "alice@laptop");
        assert_eq!(parsed[0].fingerprint, crate::identity::fingerprint(&key));
    }

    #[test]
    fn format_authorized_key_line_without_comment_has_no_trailing_space() {
        let key = [1u8; 32];
        let line = format_authorized_key_line(&key, "");
        assert!(!line.ends_with(' '));
        assert_eq!(
            line.matches(' ').count(),
            1,
            "expected exactly one space (type/key, no comment)"
        );
    }
}
