//! `wsh targets [user@]host` -- list the execution targets a host lets this key use (wsh #121).
//!
//! The host decides what to show per key. Name one with `wsh --target NAME [user@]host [command...]`.

use anyhow::{Context, Result};
use serde_json::json;
use tracing::{debug, info};
use wsh_core::messages::TargetInfo;

use crate::commands::common::{connect_client, resolve_target, save_last_session};

/// What `wsh targets` prints for a list of targets: a table, or one JSON array.
pub fn render(targets: &[TargetInfo], json_output: bool) -> String {
    if json_output {
        let items: Vec<_> = targets
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "capabilities": t.capabilities,
                })
            })
            .collect();
        return serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string());
    }
    if targets.is_empty() {
        return "No targets are available to this key.".to_string();
    }
    let mut out = format!("{:<24} {:<20} {}\n", "NAME", "CAN", "DESCRIPTION");
    for t in targets {
        out.push_str(&format!(
            "{:<24} {:<20} {}\n",
            t.name,
            t.capabilities.join(","),
            t.description.as_deref().unwrap_or("")
        ));
    }
    out.push_str(&format!("\n{} target(s).", targets.len()));
    out
}

/// List the targets of `target` ([user@]host).
pub async fn run(
    target: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let resolved = resolve_target(target, port, transport)?;
    info!(user = %resolved.user, host = %resolved.host, "listing targets");
    debug!(url = %crate::commands::common::redact_rendezvous(&resolved.url), "transport URL");
    let client = connect_client(&resolved, identity).await?;
    save_last_session(&resolved, port, identity)?;
    let result = client
        .list_targets()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to list targets");
    let _ = client.disconnect().await;
    println!("{}", render(&result?, json_output));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, description: Option<&str>, caps: &[&str]) -> TargetInfo {
        TargetInfo {
            name: name.into(),
            description: description.map(String::from),
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
        }
    }

    #[test]
    fn a_table_lists_each_target_with_what_it_can_do() {
        let out = render(
            &[
                t("web", Some("the web container"), &["exec", "file"]),
                t("db", None, &["exec"]),
            ],
            false,
        );
        assert!(out.contains("NAME"));
        assert!(out.contains("web"));
        assert!(out.contains("exec,file"));
        assert!(out.contains("the web container"));
        assert!(out.ends_with("2 target(s)."));
    }

    #[test]
    fn no_targets_says_so_and_json_is_an_array() {
        assert_eq!(render(&[], false), "No targets are available to this key.");
        let json: serde_json::Value =
            serde_json::from_str(&render(&[t("web", Some("w"), &["exec"])], true)).unwrap();
        assert_eq!(json[0]["name"], "web");
        assert_eq!(json[0]["capabilities"][0], "exec");
        assert_eq!(render(&[], true), "[]");
    }
}
