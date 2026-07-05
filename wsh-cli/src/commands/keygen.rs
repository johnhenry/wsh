//! `wsh keygen [name]` — generate an Ed25519 key pair.
//!
//! Uses the wsh-client `KeyStore` to generate and persist a new Ed25519
//! key pair. Prints the fingerprint and file paths on success.

use anyhow::{Context, Result};
use tracing::info;

/// Generate a new Ed25519 key pair and store it in the keystore.
pub async fn run(name: &str) -> Result<()> {
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;

    let (fingerprint, ssh_pub) = keystore
        .generate(name)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to generate key '{name}'"))?;

    let short_fp = &fingerprint[..fingerprint.len().min(12)];

    info!(name, fingerprint = %fingerprint, "key generated");

    println!("Generated Ed25519 key pair '{name}'");
    println!("  Fingerprint: {short_fp}");
    println!("  Public key:  {ssh_pub}");

    Ok(())
}
