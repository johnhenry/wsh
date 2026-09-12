//! `wsh copy-id [user@]host` — copy local public key to a remote host.
//!
//! Reads the local public key from the keystore, connects to the remote
//! host using password authentication, and installs it via the
//! `AuthorizedKeyAdd` protocol message (wsh #59).
//!
//! ## wsh #59 decision: a real protocol message, not a shell command
//!
//! This previously built a shell script (`mkdir -p ~/.wsh && ... >>
//! authorized_keys`) and ran it over an `exec` channel, single-quoting the
//! key with a hand-rolled `shell_single_quote` -- a correct-looking but
//! narrow escaping scheme (it assumed the string would only ever land
//! inside single quotes, on a POSIX `sh`) that every new call site had to
//! get right again. It was also CLI-only: nothing without a shell channel
//! -- notably the browser SDK, which this project is named for -- had any
//! way to install a key at all.
//!
//! Decision: make key installation a real protocol message
//! (`AuthorizedKeyAdd`/`AuthorizedKeyResult`, `spec/wsh-v1.yaml`). The
//! security check for whether this is safe is the same one every other
//! post-handshake message in this codebase already relies on: everything
//! dispatched by `wsh-server`'s `dispatch_message` runs only after
//! `AUTH_OK`, and an authenticated connection already has unrestricted
//! `exec`/`FileOp` access to this exact file (see
//! `crates/wsh-server/src/server.rs`'s `Open<ChannelKind::Exec>` and
//! `FileOp` handlers -- neither is sandboxed to a per-user home directory
//! or a capability list). `AuthorizedKeyAdd` therefore grants nothing an
//! authenticated caller couldn't already do via `exec`; it only removes
//! the shell-quoting hazard and makes the operation reachable from
//! implementations with no shell channel to build a command string for.
//! The alternative -- leaving this CLI-only with a documented reason -- was
//! considered and rejected: no part of the auth model treats "can run
//! exec" as a lesser privilege than "can append one line to
//! authorized_keys", so there was no real boundary being preserved by
//! keeping it CLI-only.

use anyhow::{Context, Result};
use dialoguer::Password;
use tracing::{debug, info};
use wsh_client::{ConnectConfig, WshClient};

use crate::commands::common::resolve_target;

/// Copy the local public key to the remote host's authorized_keys.
pub async fn run(target: &str, port: u16, identity: &str, transport: Option<&str>) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, "copy-id");

    // Load the key pair from the keystore.
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;

    let (_signing_key, verifying_key) = keystore
        .load(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to load key '{identity}'"))?;
    let public_key_raw = verifying_key.to_bytes();

    let password = load_password(&resolved.user, &resolved.host)?;
    debug!(url = %resolved.url, "transport URL");

    let client = WshClient::connect(
        &resolved.url,
        ConnectConfig {
            username: resolved.user.clone(),
            key_name: None,
            password: Some(password),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))
    .with_context(|| format!("failed to connect to {}", resolved.url))?;

    let comment = format!("{}@{}", resolved.user, resolved.host);
    let result = client
        .add_authorized_key(&public_key_raw, Some(&comment))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("key installation failed");

    let _ = client.disconnect().await;
    let added = result?;

    if added {
        println!(
            "Installed public key '{identity}' on {}@{}",
            resolved.user, resolved.host
        );
    } else {
        println!(
            "Public key '{identity}' is already installed on {}@{}",
            resolved.user, resolved.host
        );
    }

    Ok(())
}

fn load_password(user: &str, host: &str) -> Result<String> {
    if let Ok(password) = std::env::var("WSH_PASSWORD") {
        if !password.is_empty() {
            return Ok(password);
        }
    }

    Password::new()
        .with_prompt(format!("Password for {user}@{host}"))
        .allow_empty_password(false)
        .interact()
        .context("failed to read password")
}
