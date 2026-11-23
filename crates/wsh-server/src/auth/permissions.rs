//! Per-key permission scopes: what an `authorized_keys` line's options allow.
//!
//! The Node host (`src/key-options.mjs`) reads the same options with the same rules, and
//! `spec/key-options.vectors.json` holds the vectors both suites run (a key line -> the permissions,
//! and a request -> allowed or refused with a stable code), so the two cannot drift (wsh #122).
//!
//! A line is `[options] ssh-ed25519 <base64> [comment]`. `options` is one token of comma-separated
//! items, each `name` or `name=value`, where a value is `"..."` (a `\"` is a quote, any other
//! backslash is literal) or a bare token. **An option this server does not understand refuses the
//! key** (it is never loaded, and the reason is logged); nothing is skipped silently and then granted.
//!
//! | option | meaning |
//! |---|---|
//! | `restrict` | grant nothing; add back with the `permit-*` options |
//! | `permit-pty` | a pty shell (and, as a shell can run them, commands) |
//! | `permit-exec` | `exec` channels |
//! | `permit-mcp` | MCP discovery and calls |
//! | `permit-file-transfer` | file channels, `FileOp`, `wsh-fs` |
//! | `permit-relay` | relay registration, listing and connecting |
//! | `no-pty` | no pty even when otherwise permitted |
//! | `command="..."` | the only command the key may run; no pty, files, MCP or relay |
//! | `max-sessions=N` | at most N live pty/exec sessions for the key (N >= 1) |
//! | `no-agent-forwarding`, `no-port-forwarding`, `no-X11-forwarding`, `no-user-rc` | accepted, no effect |

use serde::{Deserialize, Serialize};
use wsh_core::keys::AuthorizedKey;

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

/// Why an options string was not accepted. The `code` is stable and shared with the Node host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionError {
    pub code: &'static str,
    pub reason: String,
}

impl OptionError {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// What a request is, for [`KeyPermissions::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRequest<'a> {
    OpenPty,
    OpenExec,
    OpenFile,
    /// An rpc channel and its protocol (`wsh-fs`, `wsh-host`, ...).
    OpenRpc(&'a str),
    FileOp,
    Mcp,
    Relay,
    /// `AuthorizedKeyAdd`: installing another key. The new key has no options, so only a key that is not
    /// restricted at all may do it (a restricted key would otherwise mint an unrestricted one).
    KeyAdmin,
}

/// A request the key's options do not allow. `code` is stable and shared with the Node host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub reason: String,
}

impl Refusal {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
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

/// The options this server accepts as flags, and as valued options.
const NO_OP_OPTIONS: [&str; 4] = [
    "no-agent-forwarding",
    "no-port-forwarding",
    "no-X11-forwarding",
    "no-user-rc",
];
const FLAG_OPTIONS: [&str; 7] = [
    "restrict",
    "no-pty",
    "permit-pty",
    "permit-exec",
    "permit-mcp",
    "permit-file-transfer",
    "permit-relay",
];
const VALUE_OPTIONS: [&str; 2] = ["command", "max-sessions"];

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

    /// Permissions that allow nothing: what a key gets if its options cannot be understood (fail closed).
    pub fn deny_all(fingerprint: String) -> Self {
        Self {
            fingerprint,
            scopes: Vec::new(),
            allow_pty: false,
            forced_command: None,
            max_sessions: None,
        }
    }

    /// Check if a specific scope is permitted.
    pub fn has_scope(&self, scope: &SessionScope) -> bool {
        self.scopes.contains(scope)
    }

    /// Whether a pty shell is allowed.
    pub fn can_pty(&self) -> bool {
        self.allow_pty && self.has_scope(&SessionScope::Shell)
    }

    /// Whether `exec` channels are allowed (a shell can run commands, so `permit-pty` grants it too).
    pub fn can_exec(&self) -> bool {
        self.has_scope(&SessionScope::Exec) || self.has_scope(&SessionScope::Shell)
    }

    /// Parse permissions from an authorized_keys options string; an options string this server does not
    /// understand gives [`KeyPermissions::deny_all`] (the server also never loads such a key, see
    /// [`refuse_keys_with_bad_options`]).
    pub fn from_options(fingerprint: String, options: Option<&str>) -> Self {
        Self::try_from_options(fingerprint.clone(), options)
            .unwrap_or_else(|_| Self::deny_all(fingerprint))
    }

    /// Parse permissions from an authorized_keys options string, or say why it is not understood.
    pub fn try_from_options(
        fingerprint: String,
        options: Option<&str>,
    ) -> Result<Self, OptionError> {
        let options_str = match options {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(Self::full_access(fingerprint)),
        };

        let mut seen: Vec<String> = Vec::new();
        let mut flags: Vec<String> = Vec::new();
        let mut command: Option<String> = None;
        let mut max_sessions: Option<usize> = None;

        for (name, value) in tokenize(options_str)? {
            let known = FLAG_OPTIONS.contains(&name.as_str())
                || NO_OP_OPTIONS.contains(&name.as_str())
                || VALUE_OPTIONS.contains(&name.as_str());
            if !known {
                return Err(OptionError::new(
                    "unknown-option",
                    format!("unknown option {name:?}"),
                ));
            }
            if seen.contains(&name) {
                return Err(OptionError::new(
                    "duplicate-option",
                    format!("option {name} given twice"),
                ));
            }
            seen.push(name.clone());
            if VALUE_OPTIONS.contains(&name.as_str()) {
                let Some(value) = value else {
                    return Err(OptionError::new(
                        "bad-value",
                        format!("option {name} needs a value"),
                    ));
                };
                if name == "command" {
                    if value.is_empty() || value.chars().any(|c| c.is_control()) {
                        return Err(OptionError::new(
                            "bad-value",
                            "command must be a non-empty string without control characters",
                        ));
                    }
                    command = Some(value);
                } else {
                    let ok = !value.is_empty()
                        && value.len() <= 9
                        && value.bytes().all(|b| b.is_ascii_digit())
                        && !value.starts_with('0');
                    if !ok {
                        return Err(OptionError::new(
                            "bad-value",
                            "max-sessions must be a positive whole number",
                        ));
                    }
                    max_sessions = value.parse::<usize>().ok();
                }
            } else {
                if value.is_some() {
                    return Err(OptionError::new(
                        "bad-value",
                        format!("option {name} takes no value"),
                    ));
                }
                flags.push(name);
            }
        }

        let has = |f: &str| flags.iter().any(|x| x == f);
        let restricted = has("restrict");
        let grant = |permit: &str| !restricted || has(permit);

        let mut scopes = Vec::new();
        if grant("permit-pty") {
            scopes.push(SessionScope::Shell);
        }
        if !restricted || has("permit-exec") || command.is_some() {
            scopes.push(SessionScope::Exec);
        }
        if grant("permit-mcp") {
            scopes.push(SessionScope::Mcp);
        }
        if grant("permit-file-transfer") {
            scopes.push(SessionScope::FileTransfer);
        }
        if grant("permit-relay") {
            scopes.push(SessionScope::Relay);
        }
        let mut allow_pty = !has("no-pty");

        // A key tied to one command is not a shell, a file, an MCP or a relay key, whatever else the line says.
        if command.is_some() {
            scopes = vec![SessionScope::Exec];
            allow_pty = false;
        }

        Ok(Self {
            fingerprint,
            scopes,
            allow_pty,
            forced_command: command,
            max_sessions,
        })
    }

    /// Whether this key may make `request`; `active_sessions` is how many pty/exec sessions it has open
    /// (for `max-sessions`). Same table as the Node host's `checkKeyRequest`.
    pub fn check(&self, request: KeyRequest<'_>, active_sessions: usize) -> Result<(), Refusal> {
        let no = Refusal::new;
        let forced = || no("forced-command", "key is restricted to forced exec command");
        let file_off = || {
            no(
                "file-transfer-not-permitted",
                "file transfer not permitted for this key",
            )
        };
        match request {
            KeyRequest::OpenPty
            | KeyRequest::OpenExec
            | KeyRequest::OpenFile
            | KeyRequest::OpenRpc(_) => {
                if self.forced_command.is_some() && request != KeyRequest::OpenExec {
                    return Err(forced());
                }
                match request {
                    KeyRequest::OpenPty if !self.can_pty() => {
                        return Err(no("pty-not-permitted", "PTY not permitted for this key"))
                    }
                    KeyRequest::OpenExec if !self.can_exec() => {
                        return Err(no(
                            "exec-not-permitted",
                            "exec access not permitted for this key",
                        ))
                    }
                    KeyRequest::OpenFile if !self.has_scope(&SessionScope::FileTransfer) => {
                        return Err(file_off())
                    }
                    KeyRequest::OpenRpc(protocol) => {
                        let unrestricted = self.can_pty()
                            && self.can_exec()
                            && self.has_scope(&SessionScope::Mcp)
                            && self.has_scope(&SessionScope::FileTransfer)
                            && self.has_scope(&SessionScope::Relay);
                        match protocol {
                            "wsh-fs" if !self.has_scope(&SessionScope::FileTransfer) => {
                                return Err(file_off())
                            }
                            "mcp" if !self.has_scope(&SessionScope::Mcp) => {
                                return Err(no(
                                    "mcp-not-permitted",
                                    "MCP not permitted for this key",
                                ))
                            }
                            "wsh-fs" | "mcp" | "wsh-host" => {}
                            _ if !unrestricted => {
                                return Err(no(
                                    "exec-not-permitted",
                                    "this protocol is not permitted for a restricted key",
                                ))
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                let makes_session = matches!(request, KeyRequest::OpenPty | KeyRequest::OpenExec);
                if let (true, Some(max)) = (makes_session, self.max_sessions) {
                    if active_sessions >= max {
                        return Err(Refusal::new(
                            "max-sessions",
                            format!("max sessions for this key reached ({max})"),
                        ));
                    }
                }
                Ok(())
            }
            KeyRequest::FileOp => {
                if self.forced_command.is_some() {
                    Err(forced())
                } else if self.has_scope(&SessionScope::FileTransfer) {
                    Ok(())
                } else {
                    Err(file_off())
                }
            }
            KeyRequest::Mcp => {
                if self.has_scope(&SessionScope::Mcp) {
                    Ok(())
                } else {
                    Err(no("mcp-not-permitted", "MCP not permitted for this key"))
                }
            }
            KeyRequest::Relay => {
                if self.has_scope(&SessionScope::Relay) {
                    Ok(())
                } else {
                    Err(no(
                        "relay-not-permitted",
                        "relay not permitted for this key",
                    ))
                }
            }
            KeyRequest::KeyAdmin => {
                let unrestricted = self.can_pty()
                    && self.can_exec()
                    && self.has_scope(&SessionScope::Mcp)
                    && self.has_scope(&SessionScope::FileTransfer)
                    && self.has_scope(&SessionScope::Relay)
                    && self.forced_command.is_none();
                if unrestricted {
                    Ok(())
                } else {
                    Err(no(
                        "key-admin-not-permitted",
                        "installing a key is not permitted for a restricted key",
                    ))
                }
            }
        }
    }
}

/// Split an options token into `(name, value)` items: the same tokenizer as the Node host's.
fn tokenize(text: &str) -> Result<Vec<(String, Option<String>)>, OptionError> {
    let bad = |reason: String| OptionError::new("bad-syntax", reason);
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut items = Vec::new();
    loop {
        let mut name = String::new();
        while i < n && chars[i] != ',' && chars[i] != '=' {
            let ch = chars[i];
            if ch == '"' || ch == '\'' || ch == ' ' || ch == '\t' {
                return Err(bad(format!("unexpected {ch:?} in an option name")));
            }
            name.push(ch);
            i += 1;
        }
        if name.is_empty() {
            return Err(bad("empty option (a stray comma)".into()));
        }
        let mut value = None;
        if i < n && chars[i] == '=' {
            i += 1;
            if i < n && chars[i] == '"' {
                i += 1;
                let mut v = String::new();
                let mut closed = false;
                while i < n {
                    let ch = chars[i];
                    if ch == '\\' && i + 1 < n && chars[i + 1] == '"' {
                        v.push('"');
                        i += 2;
                        continue;
                    }
                    if ch == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    v.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(bad(format!("unterminated quote in {name}=")));
                }
                if i < n && chars[i] != ',' {
                    return Err(bad(format!("text after the closing quote of {name}=")));
                }
                value = Some(v);
            } else {
                let mut v = String::new();
                while i < n && chars[i] != ',' {
                    let ch = chars[i];
                    if ch == '"' || ch == '\'' || ch == '=' || ch == ' ' || ch == '\t' {
                        return Err(bad(format!(
                            "unexpected {ch:?} in the value of {name}= (quote the value with double quotes)"
                        )));
                    }
                    v.push(ch);
                    i += 1;
                }
                value = Some(v);
            }
        }
        items.push((name, value));
        if i >= n {
            return Ok(items);
        }
        i += 1; // the comma
        if i >= n {
            return Err(bad("empty option (a trailing comma)".into()));
        }
    }
}

/// Drop every key whose options this server does not understand, logging why (wsh #122). A key that is not
/// loaded cannot log in: an option that is not understood is never ignored and then granted.
pub fn refuse_keys_with_bad_options(keys: Vec<AuthorizedKey>) -> Vec<AuthorizedKey> {
    keys.into_iter()
        .filter(|k| {
            match KeyPermissions::try_from_options(k.fingerprint.clone(), k.options.as_deref()) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(
                        fingerprint = %&k.fingerprint[..8.min(k.fingerprint.len())],
                        code = e.code,
                        "authorized_keys: key refused: {}",
                        e.reason
                    );
                    false
                }
            }
        })
        .collect()
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

    #[test]
    fn an_option_that_is_not_understood_denies_everything_never_full_access() {
        let p = KeyPermissions::from_options("fp".to_string(), Some("permit-teleport"));
        assert!(p.scopes.is_empty() && !p.allow_pty);
        let p = KeyPermissions::from_options("fp".to_string(), Some("max-sessions=0"));
        assert!(p.scopes.is_empty() && p.max_sessions.is_none());
    }

    // ── The vectors shared with the Node host (spec/key-options.vectors.json) ──────────────

    const VECTORS: &str = include_str!("../../../../spec/key-options.vectors.json");

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("vectors parse")
    }

    fn can_of(p: &KeyPermissions) -> Vec<&'static str> {
        let mut out = Vec::new();
        if p.can_pty() {
            out.push("pty");
        }
        if p.can_exec() {
            out.push("exec");
        }
        if p.has_scope(&SessionScope::Mcp) {
            out.push("mcp");
        }
        if p.has_scope(&SessionScope::FileTransfer) {
            out.push("fileTransfer");
        }
        if p.has_scope(&SessionScope::Relay) {
            out.push("relay");
        }
        out
    }

    #[test]
    fn shared_vectors_lines() {
        let v = vectors();
        let key = v["key"].as_str().unwrap();
        let placeholder = v["keyPlaceholder"].as_str().unwrap();
        for case in v["lines"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let line = case["line"].as_str().unwrap().replace(placeholder, key);
            let keys = wsh_core::keys::parse_authorized_keys(&line);
            match case["result"].as_str().unwrap() {
                "skip" => assert!(keys.is_empty(), "{name}: expected a skipped line"),
                result => {
                    assert_eq!(keys.len(), 1, "{name}: expected the line to parse to a key");
                    let parsed = KeyPermissions::try_from_options(
                        keys[0].fingerprint.clone(),
                        keys[0].options.as_deref(),
                    );
                    if result == "refused" {
                        let e = parsed.expect_err(name);
                        assert_eq!(e.code, case["code"].as_str().unwrap(), "{name}");
                        // ... and the server never loads it
                        assert!(
                            refuse_keys_with_bad_options(keys).is_empty(),
                            "{name}: a refused key must not load"
                        );
                    } else {
                        let p = parsed.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                        let want: Vec<&str> = case["can"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap())
                            .collect();
                        assert_eq!(can_of(&p), want, "{name}");
                        assert_eq!(
                            p.forced_command.as_deref(),
                            case["forcedCommand"].as_str(),
                            "{name}"
                        );
                        assert_eq!(
                            p.max_sessions,
                            case["maxSessions"].as_u64().map(|n| n as usize),
                            "{name}"
                        );
                        assert_eq!(refuse_keys_with_bad_options(keys).len(), 1, "{name}");
                    }
                }
            }
        }
    }

    #[test]
    fn shared_vectors_requests() {
        let v = vectors();
        for case in v["requests"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let options = case["options"].as_str().unwrap();
            let p = KeyPermissions::try_from_options("fp".into(), Some(options))
                .unwrap_or_else(|e| panic!("{name}: options must parse: {e:?}"));
            let r = &case["request"];
            let protocol = r["protocol"].as_str().unwrap_or("");
            let request = match (r["kind"].as_str().unwrap(), r["channel"].as_str()) {
                ("open", Some("pty")) => KeyRequest::OpenPty,
                ("open", Some("exec")) => KeyRequest::OpenExec,
                ("open", Some("file")) => KeyRequest::OpenFile,
                ("open", Some("rpc")) => KeyRequest::OpenRpc(protocol),
                ("file-op", _) => KeyRequest::FileOp,
                ("mcp", _) => KeyRequest::Mcp,
                ("relay", _) => KeyRequest::Relay,
                ("key-admin", _) => KeyRequest::KeyAdmin,
                other => panic!("{name}: unknown request {other:?}"),
            };
            let active = case["activeSessions"].as_u64().unwrap_or(0) as usize;
            let got = p.check(request, active);
            if case["allowed"].as_bool().unwrap() {
                assert_eq!(got, Ok(()), "{name}");
            } else {
                assert_eq!(
                    got.err().map(|r| r.code),
                    Some(case["code"].as_str().unwrap()),
                    "{name}"
                );
            }
        }
    }
}
