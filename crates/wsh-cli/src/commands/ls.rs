//! `wsh ls [user@]host:path` — one-shot remote directory listing (wsh #58).
//!
//! `list()` (wsh #59) already answers exactly this over the structured
//! file channel; a one-shot listing shouldn't require spinning up a full
//! interactive `wsh sftp` session just to answer "what's in this
//! directory". Path parsing is shared with `scp`/`sftp` via
//! `common::parse_endpoint` -- see that module's doc comment for why.

use anyhow::{Context, Result};
use tracing::debug;
use wsh_client::file_transfer;

use crate::commands::common::{connect_client, parse_endpoint, resolve_target, Endpoint};
use crate::commands::fs_display::format_entry_line;

/// List a remote directory and print it, one entry per line.
pub async fn run(target: &str, port: u16, identity: &str, transport: Option<&str>) -> Result<()> {
    let (user, host, path) = match parse_endpoint(target)? {
        Endpoint::Remote { user, host, path } => (user, host, path),
        Endpoint::Local(p) => anyhow::bail!(
            "wsh ls requires a remote target ([user@]host:path), got a local path: {}",
            p.display()
        ),
    };

    let target_str = format!("{user}@{host}");
    let resolved = resolve_target(&target_str, port, transport)?;
    let client = connect_client(&resolved, identity).await?;
    debug!(url = %resolved.url, path = %path, "ls");

    let result = file_transfer::list(&client, &path).await;
    let _ = client.disconnect().await;

    // A refusal (unimplemented op, unauthorized fs capability, no such
    // path) must be reported by name here -- never silently printed as an
    // empty listing indistinguishable from "this directory has nothing in
    // it" (wsh #58).
    let entries = result
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("wsh: ls: {user}@{host}:{path}"))?;

    if entries.is_empty() {
        println!("(empty directory)");
        return Ok(());
    }

    for entry in &entries {
        println!("{}", format_entry_line(entry));
    }

    Ok(())
}
