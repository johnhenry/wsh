//! File-based Ed25519 key storage for wsh.
//!
//! Keys are stored at `~/.wsh/keys/` by default:
//! - Private keys: `<name>.pem` (PKCS#8 v2 DER, base64-encoded PEM)
//! - Public keys: `<name>.pub` (SSH format: `ssh-ed25519 <base64> <comment>`)

use crate::auth;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs;
use std::path::PathBuf;
use wsh_core::{WshError, WshResult};

/// Base64 encoding table (standard alphabet).
const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Information about a stored key.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// Key name (filename stem).
    pub name: String,
    /// SHA-256 fingerprint of the public key (hex).
    pub fingerprint: String,
    /// Public key in SSH format.
    pub public_key_ssh: String,
}

/// File-based key store.
pub struct KeyStore {
    base_dir: PathBuf,
}

impl KeyStore {
    /// Create a new key store at the given directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Create a key store at the default location (`~/.wsh/keys/`).
    pub fn default_location() -> WshResult<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| WshError::Other("cannot determine home directory".into()))?;
        Ok(Self::new(home.join(".wsh").join("keys")))
    }

    /// Ensure the key store directory exists with secure permissions.
    fn ensure_dir(&self) -> WshResult<()> {
        if !self.base_dir.exists() {
            fs::create_dir_all(&self.base_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.base_dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    /// Path to the private key file.
    fn private_key_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{name}.pem"))
    }

    /// Path to the public key file.
    fn public_key_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{name}.pub"))
    }

    /// Generate a new keypair and store it.
    ///
    /// Returns the fingerprint and SSH-format public key string.
    pub fn generate(&self, name: &str) -> WshResult<(String, String)> {
        self.ensure_dir()?;

        if self.private_key_path(name).exists() {
            return Err(WshError::Other(format!("key '{name}' already exists")));
        }

        let (signing_key, verifying_key) = auth::generate_keypair();

        // Save private key as PEM
        self.save_private_key(name, &signing_key)?;

        // Save public key in SSH format
        let ssh_pub = self.format_ssh_public_key(&verifying_key, name);
        fs::write(self.public_key_path(name), &ssh_pub)?;

        let fingerprint = wsh_core::fingerprint(&verifying_key.to_bytes());

        Ok((fingerprint, ssh_pub))
    }

    /// Load a keypair by name.
    pub fn load(&self, name: &str) -> WshResult<(SigningKey, VerifyingKey)> {
        let pem_path = self.private_key_path(name);
        if !pem_path.exists() {
            return Err(WshError::UnknownKey(name.into()));
        }

        let pem_content = fs::read_to_string(&pem_path)?;
        let signing_key = self.parse_private_key_pem(&pem_content)?;
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }

    /// List all stored keys.
    pub fn list(&self) -> WshResult<Vec<KeyInfo>> {
        self.ensure_dir()?;
        let mut keys = Vec::new();

        let entries = fs::read_dir(&self.base_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pem") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let name = stem.to_string();
                    match self.load(&name) {
                        Ok((_sk, vk)) => {
                            let fingerprint = wsh_core::fingerprint(&vk.to_bytes());
                            let public_key_ssh = self.format_ssh_public_key(&vk, &name);
                            keys.push(KeyInfo {
                                name,
                                fingerprint,
                                public_key_ssh,
                            });
                        }
                        Err(e) => {
                            tracing::warn!("skipping corrupt key '{}': {}", name, e);
                        }
                    }
                }
            }
        }

        keys.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(keys)
    }

    /// Delete a keypair by name.
    pub fn delete(&self, name: &str) -> WshResult<()> {
        let pem_path = self.private_key_path(name);
        let pub_path = self.public_key_path(name);

        if !pem_path.exists() {
            return Err(WshError::UnknownKey(name.into()));
        }

        fs::remove_file(&pem_path)?;
        if pub_path.exists() {
            fs::remove_file(&pub_path)?;
        }

        Ok(())
    }

    /// Export the public key in SSH format.
    pub fn export_public(&self, name: &str) -> WshResult<String> {
        let (_sk, vk) = self.load(name)?;
        Ok(self.format_ssh_public_key(&vk, name))
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Format a verifying key as an SSH-format public key string.
    ///
    /// Format: `ssh-ed25519 <base64(ssh_wire_format)> <comment>`
    fn format_ssh_public_key(&self, vk: &VerifyingKey, comment: &str) -> String {
        let wire = encode_ssh_ed25519_wire(&vk.to_bytes());
        let b64 = base64_encode(&wire);
        format!("ssh-ed25519 {b64} {comment}")
    }

    /// Save a private key in PEM format.
    ///
    /// Uses a simplified PEM format wrapping the raw 32-byte secret key.
    fn save_private_key(&self, name: &str, sk: &SigningKey) -> WshResult<()> {
        let raw = sk.to_bytes();
        let b64 = base64_encode(&raw);

        let pem = format!(
            "-----BEGIN WSH PRIVATE KEY-----\n{}\n-----END WSH PRIVATE KEY-----\n",
            b64
        );

        let path = self.private_key_path(name);
        fs::write(&path, &pem)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Parse a PEM-encoded private key.
    fn parse_private_key_pem(&self, pem: &str) -> WshResult<SigningKey> {
        let b64: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");

        let raw = base64_decode(&b64)
            .ok_or_else(|| WshError::Other("invalid base64 in private key PEM".into()))?;

        auth::signing_key_from_bytes(&raw)
    }
}

/// Encode a 32-byte Ed25519 public key into SSH wire format.
///
/// Wire format: `[4-byte len]["ssh-ed25519"][4-byte len][32-byte key]`
fn encode_ssh_ed25519_wire(public_key: &[u8; 32]) -> Vec<u8> {
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);

    // Key type length + key type
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);

    // Key data length + key data
    wire.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    wire.extend_from_slice(public_key);

    wire
}

// ── Base64 helpers ────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;

    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        result.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push(B64_TABLE[((n >> 6) & 0x3f) as usize] as char);
        result.push(B64_TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        result.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push('=');
        result.push('=');
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        result.push(B64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        result.push(B64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        result.push(B64_TABLE[((n >> 6) & 0x3f) as usize] as char);
        result.push('=');
    }

    result
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut lookup = [255u8; 256];
    for (i, &c) in B64_TABLE.iter().enumerate() {
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
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Returns a unique temp directory for a test, isolated across parallel
    /// test threads/processes (unlike a fixed shared name, which races when
    /// `cargo test` runs tests concurrently).
    fn unique_temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wsh-keystore-test-{label}-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn base64_round_trip() {
        let data = b"hello, wsh keypair test!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn ssh_wire_format() {
        let key = [0xABu8; 32];
        let wire = encode_ssh_ed25519_wire(&key);
        // Verify structure: 4-byte len + "ssh-ed25519" + 4-byte len + 32-byte key
        assert_eq!(wire.len(), 4 + 11 + 4 + 32);
        let type_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(type_len, 11);
        assert_eq!(&wire[4..15], b"ssh-ed25519");
        let key_len = u32::from_be_bytes([wire[15], wire[16], wire[17], wire[18]]) as usize;
        assert_eq!(key_len, 32);
        assert_eq!(&wire[19..51], &key);
    }

    #[test]
    fn generate_load_delete() {
        let tmp = unique_temp_dir("generate-load-delete");
        let _ = fs::remove_dir_all(&tmp);

        let store = KeyStore::new(&tmp);

        // Generate
        let (fp, ssh_pub) = store.generate("test-key").unwrap();
        assert!(!fp.is_empty());
        assert!(ssh_pub.starts_with("ssh-ed25519 "));

        // Load
        let (sk, vk) = store.load("test-key").unwrap();
        assert_eq!(wsh_core::fingerprint(&vk.to_bytes()), fp);

        // List
        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "test-key");

        // Export
        let exported = store.export_public("test-key").unwrap();
        assert!(exported.starts_with("ssh-ed25519 "));

        // Sign/verify round-trip with loaded key
        let sig = crate::auth::sign_challenge(&sk, "test-sess", b"nonce");
        assert!(crate::auth::verify_challenge(
            &vk,
            &sig,
            "test-sess",
            b"nonce"
        ));

        // Delete
        store.delete("test-key").unwrap();
        assert!(store.load("test-key").is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn duplicate_name_errors() {
        let tmp = unique_temp_dir("duplicate-name-errors");
        let _ = fs::remove_dir_all(&tmp);

        let store = KeyStore::new(&tmp);
        store.generate("dup").unwrap();
        assert!(store.generate("dup").is_err());

        let _ = fs::remove_dir_all(&tmp);
    }
}
