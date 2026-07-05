//! MCP proxy: forward MCP requests to local MCP servers via HTTP.
//!
//! This allows the wsh server to act as a gateway, proxying MCP tool
//! calls to local MCP-compatible servers (e.g., running on localhost).

use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};
use wsh_core::messages::{McpCallPayload, McpResultPayload, McpToolSpec};

/// Configuration for a proxied MCP server.
#[derive(Debug, Clone)]
pub struct ProxiedServer {
    /// Name of the server (used as tool namespace prefix).
    pub name: String,
    /// HTTP base URL of the MCP server.
    pub url: String,
    /// Optional API key or auth token.
    pub auth_token: Option<String>,
    /// Timeout for requests in seconds.
    pub timeout_secs: u64,
}

/// MCP proxy that forwards requests to local MCP servers.
pub struct McpProxy {
    /// Registered proxied servers.
    servers: HashMap<String, ProxiedServer>,
    /// Cached tool lists per server.
    tool_cache: HashMap<String, Vec<McpToolSpec>>,
    /// HTTP client (reusable).
    http_client: reqwest::Client,
}

impl McpProxy {
    /// Create a new empty proxy.
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
            tool_cache: HashMap::new(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Register a proxied MCP server.
    pub fn register_server(&mut self, server: ProxiedServer) {
        info!(name = %server.name, url = %server.url, "registered proxied MCP server");
        self.servers.insert(server.name.clone(), server);
    }

    /// Unregister a server.
    pub fn unregister_server(&mut self, name: &str) -> bool {
        self.tool_cache.remove(name);
        self.servers.remove(name).is_some()
    }

    /// Discover tools from all registered servers via HTTP.
    ///
    /// Sends GET requests to each server's `/tools` endpoint and caches results.
    pub async fn discover_all(&mut self) -> Vec<McpToolSpec> {
        let mut all_tools = Vec::new();

        // Collect server info to avoid borrow issues
        let servers: Vec<(String, String, Option<String>, u64)> = self
            .servers
            .values()
            .map(|s| {
                (
                    s.name.clone(),
                    s.url.clone(),
                    s.auth_token.clone(),
                    s.timeout_secs,
                )
            })
            .collect();

        for (name, url, auth_token, timeout_secs) in servers {
            let tools_url = format!("{}/tools", url.trim_end_matches('/'));
            debug!(server = %name, url = %tools_url, "discovering MCP tools");

            let mut req = self
                .http_client
                .get(&tools_url)
                .timeout(Duration::from_secs(timeout_secs));

            if let Some(ref token) = auth_token {
                req = req.bearer_auth(token);
            }

            match req.send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<Vec<McpToolSpec>>().await {
                        Ok(tools) => {
                            info!(
                                server = %name,
                                tool_count = tools.len(),
                                "discovered MCP tools"
                            );
                            // Prefix tool names with server name
                            let prefixed: Vec<McpToolSpec> = tools
                                .into_iter()
                                .map(|mut t| {
                                    t.name = format!("{}.{}", name, t.name);
                                    t
                                })
                                .collect();
                            self.tool_cache.insert(name.clone(), prefixed.clone());
                            all_tools.extend(prefixed);
                        }
                        Err(e) => {
                            warn!(server = %name, error = %e, "failed to parse MCP tools response");
                            // Return cached if available
                            if let Some(cached) = self.tool_cache.get(&name) {
                                all_tools.extend(cached.clone());
                            }
                        }
                    }
                }
                Ok(response) => {
                    warn!(
                        server = %name,
                        status = %response.status(),
                        "MCP tools discovery returned non-success status"
                    );
                    if let Some(cached) = self.tool_cache.get(&name) {
                        all_tools.extend(cached.clone());
                    }
                }
                Err(e) => {
                    warn!(server = %name, error = %e, "MCP tools discovery request failed");
                    if let Some(cached) = self.tool_cache.get(&name) {
                        all_tools.extend(cached.clone());
                    }
                }
            }
        }

        all_tools
    }

    /// Manually register tools for a server (e.g., from static config).
    pub fn set_tools(&mut self, server_name: &str, tools: Vec<McpToolSpec>) {
        self.tool_cache.insert(server_name.to_string(), tools);
    }

    /// Forward an MCP call to the appropriate proxied server via HTTP.
    ///
    /// Tool names are expected to be prefixed with the server name:
    /// e.g., `servername.toolname`.
    pub async fn call(&self, call: &McpCallPayload) -> McpResultPayload {
        // Parse server name from tool name (format: "server.tool")
        let (server_name, tool_name) = match call.tool.split_once('.') {
            Some(parts) => parts,
            None => {
                return McpResultPayload {
                    result: json!({
                        "error": format!(
                            "tool name must be prefixed with server name: {}",
                            call.tool
                        ),
                    }),
                };
            }
        };

        let server = match self.servers.get(server_name) {
            Some(s) => s,
            None => {
                return McpResultPayload {
                    result: json!({
                        "error": format!("unknown MCP server: {server_name}"),
                    }),
                };
            }
        };

        let call_url = format!("{}/call", server.url.trim_end_matches('/'));
        debug!(
            server = %server.name,
            tool = %tool_name,
            url = %call_url,
            "forwarding MCP call"
        );

        let body = json!({
            "tool": tool_name,
            "arguments": call.arguments,
        });

        let mut req = self
            .http_client
            .post(&call_url)
            .json(&body)
            .timeout(Duration::from_secs(server.timeout_secs));

        if let Some(ref token) = server.auth_token {
            req = req.bearer_auth(token);
        }

        match req.send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<serde_json::Value>().await {
                    Ok(result) => McpResultPayload { result },
                    Err(e) => McpResultPayload {
                        result: json!({
                            "error": format!("failed to parse MCP result: {e}"),
                        }),
                    },
                }
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                McpResultPayload {
                    result: json!({
                        "error": format!("MCP call failed with status {status}"),
                        "body": body,
                    }),
                }
            }
            Err(e) => McpResultPayload {
                result: json!({
                    "error": format!("MCP call request failed: {e}"),
                }),
            },
        }
    }

    /// List all cached tools across all proxied servers.
    pub fn list_tools(&self) -> Vec<McpToolSpec> {
        self.tool_cache.values().flatten().cloned().collect()
    }

    /// Number of registered servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }
}
