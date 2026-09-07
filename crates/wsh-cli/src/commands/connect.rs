//! `wsh connect [user@]host` — open an interactive PTY session.
//!
//! Parses the target, loads the identity key from the keystore, connects via
//! WshClient, opens a PTY channel, and enters raw terminal mode to pipe
//! stdin/stdout between the local terminal and the remote PTY. Terminal
//! resize events are forwarded to the server.

use anyhow::{Context, Result};
use tracing::{debug, info};
use wsh_client::session::SessionOpts;
use wsh_core::messages::ChannelKind;

use crate::commands::common::{connect_client, resolve_target, save_last_session};
use crate::commands::interactive;
use crate::terminal as term;

/// Run an interactive PTY session against `target` ([user@]host).
pub async fn run(target: &str, port: u16, identity: &str, transport: Option<&str>) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, port, "connecting");
    debug!(url = %resolved.url, "transport URL");

    // Get initial terminal size.
    let (cols, rows) = term::get_terminal_size();
    info!(cols, rows, "terminal size");

    let client = connect_client(&resolved, identity).await?;
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::Pty,
            command: None,
            cols: Some(cols),
            rows: Some(rows),
            env: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to open PTY session")?;

    save_last_session(&resolved, port, identity)?;
    interactive::run_session(session, &resolved.host).await?;
    let _ = client.disconnect().await;
    info!("disconnected from {}", resolved.host);

    Ok(())
}
