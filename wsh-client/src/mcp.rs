//! MCP (Model Context Protocol) tool discovery and invocation over wsh.
//!
//! Uses the wsh control channel to discover available tools on the remote
//! server and invoke them, returning structured JSON results.

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::*;

use crate::client::WshClient;

/// Discover available MCP tools on the remote server.
///
/// Sends a `McpDiscover` control message and waits for a `McpTools` response
/// containing the list of tool specifications.
pub async fn discover_tools(client: &WshClient) -> WshResult<Vec<McpToolSpec>> {
    let envelope = Envelope {
        msg_type: MsgType::McpDiscover,
        payload: Payload::McpDiscover(McpDiscoverPayload {}),
    };

    let response = client
        .send_and_wait_public(envelope, MsgType::McpTools)
        .await?;

    match response.payload {
        Payload::McpTools(tools) => {
            tracing::info!("discovered {} MCP tools", tools.tools.len());
            Ok(tools.tools)
        }
        _ => Err(WshError::InvalidMessage(
            "expected McpTools response".into(),
        )),
    }
}

/// Call an MCP tool by name with JSON arguments.
///
/// Sends a `McpCall` control message and waits for a `McpResult` response.
pub async fn call_tool(
    client: &WshClient,
    name: &str,
    args: serde_json::Value,
) -> WshResult<serde_json::Value> {
    let envelope = Envelope {
        msg_type: MsgType::McpCall,
        payload: Payload::McpCall(McpCallPayload {
            tool: name.to_string(),
            arguments: args,
        }),
    };

    let response = client
        .send_and_wait_public(envelope, MsgType::McpResult)
        .await?;

    match response.payload {
        Payload::McpResult(result) => {
            tracing::debug!("MCP tool '{}' returned result", name);
            Ok(result.result)
        }
        Payload::Error(err) => Err(WshError::Other(format!(
            "MCP tool '{}' error [{}]: {}",
            name, err.code, err.message
        ))),
        _ => Err(WshError::InvalidMessage(
            "expected McpResult response".into(),
        )),
    }
}
