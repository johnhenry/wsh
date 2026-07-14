//! Per-key permission scopes (v1.5 stub).
//!
//! When fully implemented, authorized_keys options like `command="...",no-pty`
//! will be parsed into structured permissions attached to each key.

use serde::{Deserialize, Serialize};

/// Scopes that a session may be granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionScope {
    /// Full interactive shell access.
    Shell,
    /// Non-interactive command execution access.
    Exec,
    /// Allowed to run a single specified command only.
    Command(String),
    /// Allowed to use MCP tool bridging.
    Mcp,
    /// Allowed to open file transfer channels.
    FileTransfer,
    /// Allowed to act as a relay peer.
    Relay,
}

/// Permissions associated with an authorized key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPermissions {
    /// Fingerprint of the authorized key.
    pub fingerprint: String,
    /// Allowed scopes for sessions authenticated with this key.
    pub scopes: Vec<SessionScope>,
    /// Whether PTY allocation is allowed.
    pub allow_pty: bool,
    /// Optional forced command (overrides client request).
    pub forced_command: Option<String>,
    /// Maximum number of concurrent sessions for this key.
    pub max_sessions: Option<usize>,
}

impl KeyPermissions {
    /// Create default (full-access) permissions for a given fingerprint.
    pub fn full_access(fingerprint: String) -> Self {
        Self {
            fingerprint,
            scopes: vec![
                SessionScope::Shell,
                SessionScope::Exec,
                SessionScope::Mcp,
                SessionScope::FileTransfer,
                SessionScope::Relay,
            ],
            allow_pty: true,
            forced_command: None,
            max_sessions: None,
        }
    }

    /// Check if a specific scope is permitted.
    pub fn has_scope(&self, scope: &SessionScope) -> bool {
        self.scopes.contains(scope)
    }

    /// Parse permissions from an authorized_keys options string.
    ///
    /// Supports SSH-style key options:
    /// - `command="cmd"` → forced command, only exec allowed
    /// - `no-pty` → disallow PTY allocation
    /// - `restrict` → deny all, must combine with `permit-*`
    /// - `restrict,permit-pty` → only PTY allowed
    /// - `no-agent-forwarding`, `no-port-forwarding` → ignored (no-op)
    pub fn from_options(fingerprint: String, options: Option<&str>) -> Self {
        let options_str = match options {
            Some(s) if !s.is_empty() => s,
            _ => return Self::full_access(fingerprint),
        };

        let mut allow_pty = true;
        let mut forced_command: Option<String> = None;
        let mut max_sessions: Option<usize> = None;
        let mut restricted = false;
        let mut permit_pty = false;
        let mut permit_exec = false;
        let mut permit_mcp = false;
        let mut permit_file = false;
        let mut permit_relay = false;

        // Parse comma-separated options, handling quoted values
        for opt in split_options(options_str) {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            if let Some(cmd) = opt.strip_prefix("command=") {
                // Extract quoted command
                let cmd = cmd.trim_matches('"').trim_matches('\'');
                forced_command = Some(cmd.to_string());
                permit_exec = true;
            } else if opt == "no-pty" {
                allow_pty = false;
            } else if opt == "restrict" {
                restricted = true;
            } else if opt == "permit-pty" {
                permit_pty = true;
            } else if opt == "permit-exec" {
                permit_exec = true;
            } else if opt == "permit-mcp" {
                permit_mcp = true;
            } else if opt == "permit-file-transfer" {
                permit_file = true;
            } else if opt == "permit-relay" {
                permit_relay = true;
            } else if let Some(raw) = opt.strip_prefix("max-sessions=") {
                max_sessions = raw.parse::<usize>().ok().filter(|v| *v > 0);
            }
            // Ignore unknown options (no-agent-forwarding, etc.)
        }

        if restricted {
            // Start with nothing, add back permitted scopes
            let mut scopes = Vec::new();
            if permit_pty {
                scopes.push(SessionScope::Shell);
            }
            if permit_exec {
                scopes.push(SessionScope::Exec);
            }
            if permit_mcp {
                scopes.push(SessionScope::Mcp);
            }
            if permit_file {
                scopes.push(SessionScope::FileTransfer);
            }
            if permit_relay {
                scopes.push(SessionScope::Relay);
            }
            scopes.dedup();

            Self {
                fingerprint,
                scopes,
                allow_pty,
                forced_command,
                max_sessions,
            }
        } else {
            // Non-restricted: start with full access, remove denied scopes
            let mut perms = Self::full_access(fingerprint);
            perms.allow_pty = allow_pty;
            perms.forced_command = forced_command;
            perms.max_sessions = max_sessions;
            perms
        }
    }
}

/// Split options string by commas, respecting quoted values.
fn split_options(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '"';

    for ch in s.chars() {
        if in_quotes {
            current.push(ch);
            if ch == quote_char {
                in_quotes = false;
            }
        } else if ch == '"' || ch == '\'' {
            in_quotes = true;
            quote_char = ch;
            current.push(ch);
        } else if ch == ',' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_permit_exec_grants_exec_not_shell() {
        let p = KeyPermissions::from_options("fp".to_string(), Some("restrict,permit-exec"));
        assert!(p.has_scope(&SessionScope::Exec));
        assert!(!p.has_scope(&SessionScope::Shell));
    }

    #[test]
    fn command_option_sets_forced_command() {
        let p = KeyPermissions::from_options(
            "fp".to_string(),
            Some("restrict,command=\"/usr/bin/uptime\""),
        );
        assert_eq!(p.forced_command.as_deref(), Some("/usr/bin/uptime"));
        assert!(p.has_scope(&SessionScope::Exec));
    }

    #[test]
    fn max_sessions_parsed_when_positive() {
        let p = KeyPermissions::from_options("fp".to_string(), Some("max-sessions=3"));
        assert_eq!(p.max_sessions, Some(3));
    }
}
