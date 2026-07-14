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
}
