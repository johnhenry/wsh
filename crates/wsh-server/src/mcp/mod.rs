//! MCP (Model Context Protocol) tool bridging and proxying.

pub mod bridge;
pub mod calls;
pub mod proxy;

pub use bridge::McpBridge;
pub use calls::McpCalls;
pub use proxy::McpProxy;
