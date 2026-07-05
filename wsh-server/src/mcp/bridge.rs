//! MCP bridge: auto-wrap CLI tools as MCP tools.
//!
//! Executes commands via `tokio::process::Command` and returns the output
//! as structured MCP results.

use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::process::Command;
use tracing::{debug, info, warn};
use wsh_core::messages::{McpCallPayload, McpResultPayload, McpToolSpec};
use wsh_core::{WshError, WshResult};

/// A registered CLI tool that can be invoked via MCP.
#[derive(Debug, Clone)]
pub struct CliToolDefinition {
    /// MCP tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The command template. `{arg}` placeholders are substituted from arguments.
    pub command: String,
    /// Expected argument names and their descriptions.
    pub parameters: HashMap<String, String>,
    /// Working directory (optional).
    pub working_dir: Option<String>,
    /// Environment variables to set.
    pub env: HashMap<String, String>,
    /// Timeout in seconds (0 = no timeout).
    pub timeout_secs: u64,
}

/// MCP bridge that wraps CLI tools.
pub struct McpBridge {
    tools: HashMap<String, CliToolDefinition>,
}

impl McpBridge {
    /// Create a new empty bridge.
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a CLI tool.
    pub fn register(&mut self, tool: CliToolDefinition) {
        info!(name = %tool.name, command = %tool.command, "registered MCP CLI tool");
        self.tools.insert(tool.name.clone(), tool);
    }

    /// Unregister a tool by name.
    pub fn unregister(&mut self, name: &str) -> bool {
        self.tools.remove(name).is_some()
    }

    /// List all registered tools as MCP tool specs.
    pub fn list_tools(&self) -> Vec<McpToolSpec> {
        self.tools
            .values()
            .map(|tool| {
                let mut properties = serde_json::Map::new();
                for (param_name, param_desc) in &tool.parameters {
                    properties.insert(
                        param_name.clone(),
                        json!({
                            "type": "string",
                            "description": param_desc,
                        }),
                    );
                }

                McpToolSpec {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    parameters: json!({
                        "type": "object",
                        "properties": properties,
                    }),
                }
            })
            .collect()
    }

    /// Call a registered tool with the given arguments.
    pub async fn call(&self, call: &McpCallPayload) -> McpResultPayload {
        let tool = match self.tools.get(&call.tool) {
            Some(t) => t,
            None => {
                return McpResultPayload {
                    result: json!({
                        "error": format!("unknown tool: {}", call.tool),
                    }),
                };
            }
        };

        match self.execute_tool(tool, &call.arguments).await {
            Ok(output) => McpResultPayload { result: output },
            Err(e) => McpResultPayload {
                result: json!({
                    "error": e.to_string(),
                }),
            },
        }
    }

    /// Execute a CLI tool and capture its output.
    async fn execute_tool(&self, tool: &CliToolDefinition, arguments: &Value) -> WshResult<Value> {
        // Build the command string by substituting arguments
        let mut command_str = tool.command.clone();
        if let Some(obj) = arguments.as_object() {
            for (key, value) in obj {
                let placeholder = format!("{{{key}}}");
                let replacement = match value {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                command_str = command_str.replace(&placeholder, &replacement);
            }
        }

        debug!(tool = %tool.name, command = %command_str, "executing MCP CLI tool");

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&command_str);

        // Set working directory
        if let Some(ref dir) = tool.working_dir {
            cmd.current_dir(dir);
        }

        // Set environment
        for (key, value) in &tool.env {
            cmd.env(key, value);
        }

        // Execute with optional timeout
        let output = if tool.timeout_secs > 0 {
            let duration = std::time::Duration::from_secs(tool.timeout_secs);
            tokio::time::timeout(duration, cmd.output())
                .await
                .map_err(|_| WshError::Timeout)?
                .map_err(WshError::Io)?
        } else {
            cmd.output().await.map_err(WshError::Io)?
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        if !output.status.success() {
            warn!(
                tool = %tool.name,
                exit_code,
                stderr = %stderr.chars().take(200).collect::<String>(),
                "CLI tool exited with error"
            );
        }

        Ok(json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        }))
    }

    /// Check if a tool is registered.
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Number of registered tools.
    pub fn count(&self) -> usize {
        self.tools.len()
    }
}
