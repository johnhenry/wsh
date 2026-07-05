//! `wsh sessions` / `wsh attach` / `wsh detach` — session management.
//!
//! - `sessions`: list active sessions on the connected host
//! - `attach <session>`: reattach to a named/ID'd session
//! - `detach`: detach from the current session (typically Ctrl+\ in interactive mode)

use anyhow::{Context, Result};
use tracing::info;

use crate::commands::common::{
    clear_active_attachment, connect_client, load_active_attachment, load_last_session,
    resolve_target, save_active_attachment,
};

/// List active sessions on the most recently connected host.
///
/// Reads the last-connected host from `~/.wsh/last_session` and queries
/// the server for active sessions.
pub async fn run_list() -> Result<()> {
    let last = load_last_session()?
        .context("no previous session found (connect once before using `wsh sessions`)")?;
    let target = format!("{}@{}", last.user, last.host);
    let resolved = resolve_target(&target, last.port, last.transport.as_deref())?;
    let client = connect_client(&resolved, &last.identity).await?;
    let sessions = client
        .list_remote_sessions()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to fetch sessions from server")?;

    println!(
        "{:<24} {:<12} {:<10} {:<8} {:<8} {}",
        "SESSION_ID", "OWNER", "ATTACHED", "IDLE", "CREATED", "NAME"
    );
    println!(
        "{:<24} {:<12} {:<10} {:<8} {:<8} {}",
        "----------", "-----", "--------", "----", "-------", "----"
    );
    if sessions.is_empty() {
        println!("(no visible sessions)");
    } else {
        for s in &sessions {
            println!(
                "{:<24} {:<12} {:<10} {:<8} {:<8} {}",
                s.session_id,
                s.username,
                s.attached_count,
                s.idle_secs,
                s.created_at_secs,
                s.name.as_deref().unwrap_or("-"),
            );
        }
    }
    let _ = client.disconnect().await;

    Ok(())
}

/// Reattach to a session by name or ID.
pub async fn run_attach(
    session: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
) -> Result<()> {
    info!(session = %session, "attaching");
    let last = load_last_session()?
        .context("no previous session found (connect once before using `wsh attach`)")?;
    let target = format!("{}@{}", last.user, last.host);
    let effective_transport = transport.or(last.transport.as_deref());
    let resolved = resolve_target(&target, port, effective_transport)?;
    let effective_identity = if identity.is_empty() {
        &last.identity
    } else {
        identity
    };
    let client = connect_client(&resolved, effective_identity).await?;
    client
        .attach_session(session, false)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to attach to session '{session}'"))?;
    save_active_attachment(session)?;
    println!("attached to session '{session}'");
    let _ = client.disconnect().await;
    Ok(())
}

/// Detach from the current session.
///
/// In interactive mode, this is typically invoked via the escape sequence
/// (Ctrl+\). As a standalone command, it sends a detach message to the
/// currently attached session.
pub async fn run_detach() -> Result<()> {
    info!("detach requested");
    let last = load_last_session()?
        .context("no previous session found (connect once before using `wsh detach`)")?;
    let session_id = load_active_attachment()?
        .context("no active attachment found (use `wsh attach <session_id>` first)")?;

    let target = format!("{}@{}", last.user, last.host);
    let resolved = resolve_target(&target, last.port, last.transport.as_deref())?;
    let client = connect_client(&resolved, &last.identity).await?;
    client
        .detach_session(&session_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to detach from session '{session_id}'"))?;
    clear_active_attachment()?;
    println!("detached from session '{session_id}'");
    let _ = client.disconnect().await;
    Ok(())
}
