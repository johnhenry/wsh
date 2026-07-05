//! Client configuration at `~/.wsh/config.toml`.
//!
//! Provides default host, port, identity, and transport settings.
//! CLI flags always override config file values.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

/// Top-level config file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default connection settings.
    #[serde(default)]
    pub default: DefaultConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default: DefaultConfig::default(),
        }
    }
}

/// Default connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    /// Default remote host (empty = none).
    #[serde(default)]
    pub host: String,

    /// Default server port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Default identity (key name).
    #[serde(default = "default_identity")]
    pub identity: String,

    /// Transport preference: "auto", "ws", or "wt".
    #[serde(default = "default_transport")]
    pub transport: String,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_port(),
            identity: default_identity(),
            transport: default_transport(),
        }
    }
}

fn default_port() -> u16 {
    4422
}

fn default_identity() -> String {
    "default".to_string()
}

fn default_transport() -> String {
    "auto".to_string()
}

impl Config {
    /// Load configuration from a TOML file, returning defaults if the file
    /// does not exist.
    pub fn load(path: &str) -> Result<Self> {
        let path = Path::new(path);
        if !path.exists() {
            debug!(path = %path.display(), "config file not found, using defaults");
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config at {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config at {}", path.display()))?;

        debug!(path = %path.display(), "loaded config");
        Ok(config)
    }

    /// Save the configuration to a TOML file.
    #[allow(dead_code)]
    pub fn save(&self, path: &str) -> Result<()> {
        let content = toml::to_string_pretty(self).context("failed to serialize config")?;

        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
            .with_context(|| format!("failed to write config to {}", path.display()))?;

        Ok(())
    }
}

/// Parse a `[user@]host` string into `(user, host)`.
///
/// If no user is specified, defaults to the current system username (or "root").
pub fn parse_target(target: &str) -> Result<(String, String)> {
    if let Some(at_pos) = target.find('@') {
        let user = &target[..at_pos];
        let host = &target[at_pos + 1..];
        if user.is_empty() {
            anyhow::bail!("empty username in target '{target}'");
        }
        if host.is_empty() {
            anyhow::bail!("empty host in target '{target}'");
        }
        Ok((user.to_string(), host.to_string()))
    } else {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "root".into());
        if target.is_empty() {
            anyhow::bail!("empty host");
        }
        Ok((user, target.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_at_host() {
        let (user, host) = parse_target("alice@example.com").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn parse_host_only() {
        let (user, host) = parse_target("example.com").unwrap();
        assert!(!user.is_empty());
        assert_eq!(host, "example.com");
    }

    #[test]
    fn parse_empty_user_fails() {
        assert!(parse_target("@example.com").is_err());
    }

    #[test]
    fn parse_empty_host_fails() {
        assert!(parse_target("alice@").is_err());
    }

    #[test]
    fn parse_empty_target_fails() {
        assert!(parse_target("").is_err());
    }

    #[test]
    fn default_config_values() {
        let cfg = Config::default();
        assert_eq!(cfg.default.port, 4422);
        assert_eq!(cfg.default.identity, "default");
        assert_eq!(cfg.default.transport, "auto");
        assert!(cfg.default.host.is_empty());
    }

    #[test]
    fn parse_toml_config() {
        let toml_str = r#"
[default]
host = "myserver.com"
port = 5000
identity = "work"
transport = "wt"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.default.host, "myserver.com");
        assert_eq!(cfg.default.port, 5000);
        assert_eq!(cfg.default.identity, "work");
        assert_eq!(cfg.default.transport, "wt");
    }

    #[test]
    fn parse_partial_toml_config() {
        let toml_str = r#"
[default]
host = "example.com"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.default.host, "example.com");
        assert_eq!(cfg.default.port, 4422); // default
        assert_eq!(cfg.default.identity, "default"); // default
    }
}
