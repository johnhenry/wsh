//! `wsh copy-id [user@]host` — copy local public key to a remote host.
//!
//! Reads the local public key from the keystore, connects to the remote host
//! using password authentication, and installs the key into
//! `~/.wsh/authorized_keys` via a remote shell command.

use anyhow::{Context, Result};
use dialoguer::Password;
use std::io::Write as _;
use tracing::{debug, info};
use wsh_client::{ConnectConfig, WshClient};
use wsh_core::messages::ChannelKind;

use crate::commands::common::resolve_target;

/// Copy the local public key to the remote host's authorized_keys.
pub async fn run(target: &str, port: u16, identity: &str, transport: Option<&str>) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, "copy-id");

    // Load the key pair from the keystore.
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;

    let pub_key_ssh = keystore
        .export_public(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to export public key '{identity}'"))?;

    if pub_key_ssh.is_empty() {
        anyhow::bail!("public key for '{identity}' is empty");
    }

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

    let result = async {
        let install_command = build_install_command(&pub_key_ssh);
        let session = client
            .open_session(wsh_client::SessionOpts {
                kind: ChannelKind::Exec,
                command: Some(install_command),
                cols: None,
                rows: None,
                env: None,
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("failed to open remote shell for key installation")?;

        let mut stdout = std::io::stdout().lock();
        let mut output = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = session
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("failed reading remote output")?;
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
            stdout
                .write_all(&buf[..n])
                .context("failed writing remote output")?;
            stdout.flush().context("failed flushing stdout")?;
        }

        let exit_code = session.exit_code().await.unwrap_or(1);
        let _ = session.close().await;
        if exit_code != 0 {
            let remote_output = String::from_utf8_lossy(&output);
            anyhow::bail!(
                "remote key installation failed with exit code {exit_code}: {}",
                remote_output.trim()
            );
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = client.disconnect().await;
    result?;

    println!(
        "Installed public key '{identity}' on {}@{}",
        resolved.user, resolved.host
    );

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

fn build_install_script(public_key_ssh: &str) -> String {
    let quoted_key = shell_single_quote(public_key_ssh);
    format!(
        "set -eu\n\
mkdir -p \"$HOME/.wsh\"\n\
chmod 700 \"$HOME/.wsh\"\n\
touch \"$HOME/.wsh/authorized_keys\"\n\
chmod 600 \"$HOME/.wsh/authorized_keys\"\n\
if ! grep -qxF -- {quoted_key} \"$HOME/.wsh/authorized_keys\" 2>/dev/null; then\n\
  printf '%s\\n' {quoted_key} >> \"$HOME/.wsh/authorized_keys\"\n\
fi\n\
exit $?\n"
    )
}

fn build_install_command(public_key_ssh: &str) -> String {
    format!(
        "sh -lc {}",
        shell_single_quote(&build_install_script(public_key_ssh))
    )
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::{build_install_command, build_install_script, shell_single_quote};

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(shell_single_quote("ab'cd"), "'ab'\"'\"'cd'");
    }

    #[test]
    fn install_script_is_idempotent_and_targets_wsh_authorized_keys() {
        let script = build_install_script("ssh-ed25519 AAA test@example");
        assert!(script.contains("grep -qxF -- 'ssh-ed25519 AAA test@example'"));
        assert!(script.contains("\"$HOME/.wsh/authorized_keys\""));
        assert!(script.contains("printf '%s\\n'"));
    }

    #[test]
    fn install_command_wraps_script_in_sh_lc() {
        let command = build_install_command("ssh-ed25519 AAA test@example");
        assert!(command.starts_with("sh -lc 'set -eu"));
        assert!(command.contains("\"$HOME/.wsh/authorized_keys\""));
    }
}
