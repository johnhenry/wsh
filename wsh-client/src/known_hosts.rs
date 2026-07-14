//! Trust-on-first-use (TOFU) host key verification for wsh.
//!
//! Stores known host fingerprints at `~/.wsh/known_hosts`.
//! Format: one `host fingerprint` pair per line.

use std::fs;
use std::path::PathBuf;
use wsh_core::{WshError, WshResult};

/// Result of verifying a host's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStatus {
    /// The host is known and the fingerprint matches.
    Known,
    /// The host has never been seen before.
    Unknown,
    /// The host is known but the fingerprint has changed (potential MITM).
    Changed {
        /// The previously stored fingerprint.
        expected: String,
    },
}

/// Known hosts file manager.
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    /// Create a new known hosts manager for the given file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Create a known hosts manager at the default location (`~/.wsh/known_hosts`).
    pub fn default_location() -> WshResult<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| WshError::Other("cannot determine home directory".into()))?;
        Ok(Self::new(home.join(".wsh").join("known_hosts")))
    }

    /// Verify a host's fingerprint against stored records.
    pub fn verify_host(&self, host: &str, fingerprint: &str) -> WshResult<HostStatus> {
        let entries = self.load_entries()?;

        for (stored_host, stored_fp) in &entries {
            if stored_host == host {
                if stored_fp == fingerprint {
                    return Ok(HostStatus::Known);
                } else {
                    return Ok(HostStatus::Changed {
                        expected: stored_fp.clone(),
                    });
                }
            }
        }

        Ok(HostStatus::Unknown)
    }

    /// Add or update a host's fingerprint.
    pub fn add_host(&self, host: &str, fingerprint: &str) -> WshResult<()> {
        let mut entries = self.load_entries()?;

        // Remove existing entry for this host (if any)
        entries.retain(|(h, _)| h != host);
        entries.push((host.to_string(), fingerprint.to_string()));

        self.save_entries(&entries)
    }

    /// Remove a host entry.
    pub fn remove_host(&self, host: &str) -> WshResult<bool> {
        let mut entries = self.load_entries()?;
        let len_before = entries.len();
        entries.retain(|(h, _)| h != host);
        let removed = entries.len() < len_before;

        if removed {
            self.save_entries(&entries)?;
        }

        Ok(removed)
    }

    /// List all known hosts and their fingerprints.
    pub fn list(&self) -> WshResult<Vec<(String, String)>> {
        self.load_entries()
    }

    // ── Internal ─────────────────────────────────────────────────────

    /// Load all entries from the known hosts file.
    fn load_entries(&self) -> WshResult<Vec<(String, String)>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.path)?;
        let entries = content
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let mut parts = line.splitn(2, ' ');
                let host = parts.next()?.to_string();
                let fp = parts.next()?.trim().to_string();
                if fp.is_empty() {
                    return None;
                }
                Some((host, fp))
            })
            .collect();

        Ok(entries)
    }

    /// Save all entries back to the known hosts file.
    fn save_entries(&self, entries: &[(String, String)]) -> WshResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
        }

        let content: String = entries
            .iter()
            .map(|(host, fp)| format!("{host} {fp}"))
            .collect::<Vec<_>>()
            .join("\n");

        fs::write(&self.path, content + "\n")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_known_hosts(name: &str) -> KnownHosts {
        // Use a unique directory per test (rather than a single shared
        // `wsh-known-hosts-test/` parent) so parallel test threads don't
        // race on removing/creating that shared parent directory.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wsh-known-hosts-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join(name);
        KnownHosts::new(path)
    }

    #[test]
    fn unknown_host() {
        let kh = temp_known_hosts("unknown");
        assert_eq!(
            kh.verify_host("example.com", "abc123").unwrap(),
            HostStatus::Unknown
        );
    }

    #[test]
    fn add_and_verify_known() {
        let kh = temp_known_hosts("known");
        kh.add_host("example.com", "abc123").unwrap();
        assert_eq!(
            kh.verify_host("example.com", "abc123").unwrap(),
            HostStatus::Known
        );
    }

    #[test]
    fn detect_changed_fingerprint() {
        let kh = temp_known_hosts("changed");
        kh.add_host("example.com", "abc123").unwrap();
        assert_eq!(
            kh.verify_host("example.com", "def456").unwrap(),
            HostStatus::Changed {
                expected: "abc123".to_string()
            }
        );
    }

    #[test]
    fn update_host() {
        let kh = temp_known_hosts("update");
        kh.add_host("example.com", "abc123").unwrap();
        kh.add_host("example.com", "def456").unwrap();
        assert_eq!(
            kh.verify_host("example.com", "def456").unwrap(),
            HostStatus::Known
        );
    }

    #[test]
    fn remove_host() {
        let kh = temp_known_hosts("remove");
        kh.add_host("example.com", "abc123").unwrap();
        assert!(kh.remove_host("example.com").unwrap());
        assert_eq!(
            kh.verify_host("example.com", "abc123").unwrap(),
            HostStatus::Unknown
        );
    }

    #[test]
    fn list_hosts() {
        let kh = temp_known_hosts("list");
        kh.add_host("host1.com", "fp1").unwrap();
        kh.add_host("host2.com", "fp2").unwrap();
        let list = kh.list().unwrap();
        assert_eq!(list.len(), 2);
    }
}
