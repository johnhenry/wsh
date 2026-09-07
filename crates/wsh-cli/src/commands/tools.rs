//! `wsh tools [host]` — discover MCP tools on a remote host.
//!
//! Connects to the specified (or configured default) host, sends an
//! McpDiscover message, and prints the available tools in a table.

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::commands::common::{connect_client, resolve_target, save_last_session};
use crate::config::parse_target;

/// List MCP tools available on a remote host.
pub async fn run(
    host: Option<&str>,
    port: u16,
    identity: &str,
    transport: Option<&str>,
) -> Result<()> {
    let host = host.unwrap_or("localhost");
    info!(host = %host, "discovering MCP tools");

    // Parse target (may include user@).
    let (user, resolved_host) = if host.contains('@') {
        parse_target(host)?
    } else {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "root".into());
        (user, host.to_string())
    };
    let target = format!("{user}@{resolved_host}");
    let resolved = resolve_target(&target, port, transport)?;
    debug!(url = %resolved.url, user = %resolved.user, "transport URL");
    let client = connect_client(&resolved, identity).await?;
    save_last_session(&resolved, port, identity)?;

    let tools = wsh_client::mcp::discover_tools(&client)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to discover MCP tools")?;

    if tools.is_empty() {
        println!("No MCP tools available on {resolved_host}.");
        let _ = client.disconnect().await;
        return Ok(());
    }

    println!("{:<24} {}", "NAME", "DESCRIPTION");
    println!("{:<24} {}", "----", "-----------");
    for tool in &tools {
        println!("{:<24} {}", tool.name, tool.description);
    }
    println!("\n{} tool(s) available.", tools.len());
    let _ = client.disconnect().await;

    Ok(())
}
