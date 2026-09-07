//! `wsh keys` — list stored key pairs with fingerprints.
//!
//! Uses the wsh-client `KeyStore` to enumerate all stored keys and prints
//! a table showing the key name, short fingerprint, and SSH public key.

use anyhow::{Context, Result};

/// List all stored key pairs.
pub async fn run() -> Result<()> {
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;

    let keys = keystore
        .list()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to list keys")?;

    if keys.is_empty() {
        println!("No keys found. Run `wsh keygen` to generate a key pair.");
        return Ok(());
    }

    // Collect all fingerprints for short-prefix computation.
    let all_fps: Vec<&str> = keys.iter().map(|k| k.fingerprint.as_str()).collect();

    // Print table header.
    println!("{:<16} {:<14} {}", "NAME", "FINGERPRINT", "PUBLIC KEY");
    println!(
        "{:<16} {:<14} {}",
        "\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
    );

    for key in &keys {
        let short_fp = wsh_core::short_fingerprint(&key.fingerprint, &all_fps, 8);
        // Truncate the SSH public key for display.
        let pub_display = if key.public_key_ssh.len() > 40 {
            format!("{}...", &key.public_key_ssh[..40])
        } else {
            key.public_key_ssh.clone()
        };
        println!("{:<16} {:<14} {}", key.name, short_fp, pub_display);
    }

    println!("\n{} key(s) found.", keys.len());

    Ok(())
}
