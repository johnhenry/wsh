//! `wsh user@host command` — one-off remote command execution.
//!
//! Connects to the remote host, opens an exec channel with the given command,
//! pipes stdout to the local terminal, and exits with the remote exit code.

use anyhow::{Context, Result};
use std::io::Write as _;
use tracing::{debug, info};
use wsh_client::session::SessionOpts;
use wsh_core::messages::ChannelKind;

use crate::commands::common::{connect_client, resolve_target, save_last_session};

/// Execute a remote command and print its output.
pub async fn run(
    target: &str,
    command: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, command = %command, "exec");
    debug!(url = %resolved.url, "transport URL");

    let client = connect_client(&resolved, identity).await?;
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::Exec,
            command: Some(command.to_string()),
            cols: None,
            rows: None,
            env: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to open exec session")?;
    save_last_session(&resolved, port, identity)?;

    let mut stdout = std::io::stdout().lock();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = session
            .read(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("failed reading exec output")?;
        if n == 0 {
            break;
        }
        stdout
            .write_all(&buf[..n])
            .context("failed writing exec output")?;
        stdout.flush().context("failed flushing stdout")?;
    }

    let exit_code = session.exit_code().await.unwrap_or(0);
    let _ = session.close().await;
    let _ = client.disconnect().await;
    if exit_code != 0 {
        eprintln!("wsh: remote command exited with code {exit_code}");
        std::process::exit(exit_code);
    }

    Ok(())
}
