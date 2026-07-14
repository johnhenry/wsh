//! Known hosts verification for the CLI.
//!
//! Wraps `wsh_client::KnownHosts` with interactive user prompts via dialoguer.
//! On first connection, the user is prompted to accept the server's key.
//! On subsequent connections, the stored fingerprint is compared and a
//! warning is shown if it has changed.

use anyhow::{Context, Result};
use dialoguer::Confirm;
use tracing::{debug, warn};

/// Check a server's fingerprint against known_hosts and prompt the user
/// if the host is unknown or the fingerprint has changed.
///
/// Returns `Ok(())` if the user accepts the host, or an error if they reject it.
pub fn verify(host: &str, port: u16, server_fingerprint: &str) -> Result<()> {
    let known_hosts = wsh_client::KnownHosts::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize known_hosts")?;

    let host_key = format!("{host}:{port}");

    let status = known_hosts
        .verify_host(&host_key, server_fingerprint)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match status {
        wsh_client::HostStatus::Known => {
            debug!(host = %host_key, "host verified");
            Ok(())
        }
        wsh_client::HostStatus::Unknown => {
            let short_fp = &server_fingerprint[..server_fingerprint.len().min(16)];
            eprintln!("The authenticity of host '{host_key}' cannot be established.");
            eprintln!("Server key fingerprint is {short_fp}.");

            let accept = Confirm::new()
                .with_prompt("Are you sure you want to continue connecting?")
                .default(false)
                .interact()
                .context("failed to read user input")?;

            if !accept {
                anyhow::bail!("host key verification failed — connection aborted by user");
            }

            // Store the fingerprint.
            known_hosts
                .add_host(&host_key, server_fingerprint)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            eprintln!("Warning: Permanently added '{host_key}' to the list of known hosts.");

            Ok(())
        }
        wsh_client::HostStatus::Changed { expected } => {
            let short_expected = &expected[..expected.len().min(16)];
            let short_new = &server_fingerprint[..server_fingerprint.len().min(16)];

            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!    @");
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
            eprintln!("The server key fingerprint for '{host_key}' has changed.");
            eprintln!("  Previous: {short_expected}");
            eprintln!("  Current:  {short_new}");

            warn!(
                host = %host_key,
                old_fp = %short_expected,
                new_fp = %short_new,
                "host key has changed"
            );

            let accept = Confirm::new()
                .with_prompt("Do you want to update the known host and continue?")
                .default(false)
                .interact()
                .context("failed to read user input")?;

            if !accept {
                anyhow::bail!(
                    "host key verification failed — fingerprint mismatch for '{host_key}'"
                );
            }

            // Update the stored fingerprint.
            known_hosts
                .add_host(&host_key, server_fingerprint)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            eprintln!("Warning: Updated host key for '{host_key}'.");

            Ok(())
        }
    }
}
