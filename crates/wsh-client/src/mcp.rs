//! MCP (Model Context Protocol) tool discovery and invocation over wsh.
//!
//! Uses the wsh control channel to discover available tools on the remote
//! server and invoke them, returning structured JSON results.

use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::*;

use crate::client::{WshClient, MCP_CALL_ID_FEATURE};

/// Monotonic source for call_id values, unique within this process.
static CALL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    // Only send a call_id to a server that echoes it. McpCallPayload is
    // deny_unknown_fields, so an unsolicited call_id makes an older server
    // reject the call rather than ignore the field.
    let call_id = if client.has_feature(MCP_CALL_ID_FEATURE).await {
        Some(format!(
            "rs-{}",
            CALL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    } else {
        None
    };

    let envelope = Envelope {
        msg_type: MsgType::McpCall,
        payload: Payload::McpCall(McpCallPayload {
            tool: name.to_string(),
            arguments: args,
            call_id: call_id.clone(),
        }),
    };

    let response = match call_id.clone() {
        // Correlated: take only the McpResult echoing this call's id. A
        // responder that echoes nothing is matched on type, which is all an
        // older peer can offer.
        Some(id) => {
            client
                .send_and_wait_matching_public(
                    envelope,
                    MsgType::McpResult,
                    Box::new(move |env| match &env.payload {
                        Payload::McpResult(r) => {
                            r.call_id.is_none() || r.call_id.as_deref() == Some(id.as_str())
                        }
                        _ => true,
                    }),
                )
                .await?
        }
        None => {
            client
                .send_and_wait_public(envelope, MsgType::McpResult)
                .await?
        }
    };

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
