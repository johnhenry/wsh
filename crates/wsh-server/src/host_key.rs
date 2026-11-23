//! The server's own Ed25519 identity (wsh #59, #145): a key file, created with mode 0600 on first
//! start, in the same PKCS#8 PEM format the Node host (`createWshServer({ hostKey: { file } })`)
//! reads and writes. The wire shape (the `host-key` / `host-key-sig` features, the client's
//! `host-key-nonce`) is `wsh_core::host_key`.

use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::path::Path;
use wsh_core::{WshError, WshResult};

/// This server's identity: the key it proves possession of, and what its logins are bound to.
pub struct HostIdentity {
    key: SigningKey,
    /// Hex SHA-256 of the public key -- `ServerHello.host_fingerprint`.
    pub fingerprint: String,
    /// Accept only logins bound to this connection (`channel-binding-required`).
    pub require_channel_binding: bool,
}

impl HostIdentity {
    /// A fresh in-memory key (tests).
    #[cfg(test)]
    pub fn ephemeral(require_channel_binding: bool) -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self::from_key(SigningKey::from_bytes(&seed), require_channel_binding)
    }

    fn from_key(key: SigningKey, require_channel_binding: bool) -> Self {
        let fingerprint = wsh_core::fingerprint(&key.verifying_key().to_bytes());
        Self {
            key,
            fingerprint,
            require_channel_binding,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Load the key at `path`, creating it (mode 0600, parent directories included) if there is
    /// none. A key file other users can read is refused: it is the server's identity.
    pub fn load_or_create(path: &Path, require_channel_binding: bool) -> WshResult<Self> {
        let pem = match std::fs::read_to_string(path) {
            Ok(pem) => {
                check_private(path)?;
                pem
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(path)?,
            Err(e) => return Err(e.into()),
        };
        let key = SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
            WshError::Other(format!(
                "host key {} is not an Ed25519 PKCS#8 PEM key: {e}",
                path.display()
            ))
        })?;
        Ok(Self::from_key(key, require_channel_binding))
    }
}

fn create(path: &Path) -> WshResult<String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let pem = SigningKey::from_bytes(&seed)
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| WshError::Other(format!("cannot encode the host key: {e}")))?
        .to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(pem.as_bytes())?;
            f.sync_all()?;
            tracing::info!(path = %path.display(), "created host key");
            Ok(pem)
        }
        // Another start won the race: use its key.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let pem = std::fs::read_to_string(path)?;
            check_private(path)?;
            Ok(pem)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn check_private(path: &Path) -> WshResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(WshError::Other(format!(
            "host key {} is readable by other users (mode {:o}); chmod 600 it",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> WshResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "wsh-hostkey-{}-{}",
            std::process::id(),
            wsh_core::host_key::new_nonce()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn created_on_first_start_0600_and_stable_afterwards() {
        let d = dir();
        let path = d.join("sub").join("host_key");
        let a = HostIdentity::load_or_create(&path, false).unwrap();
        let b = HostIdentity::load_or_create(&path, false).unwrap();
        assert_eq!(
            a.fingerprint, b.fingerprint,
            "the same key on the next start"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let path = d.join("host_key");
        HostIdentity::load_or_create(&path, false).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = HostIdentity::load_or_create(&path, false)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("readable by other users"), "{err}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_file_that_is_not_an_ed25519_key_is_refused() {
        let d = dir();
        let path = d.join("host_key");
        std::fs::write(&path, "not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(HostIdentity::load_or_create(&path, false).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
