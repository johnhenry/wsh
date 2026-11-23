//! Which environment variables a client may set for the command or shell this
//! server runs (`Open.env`), wsh #126 / #145.
//!
//! The default is an allow-list in the spirit of sshd's `AcceptEnv` and the same
//! list the Node host uses: `TERM`, `COLORTERM`, `LANG`, `LANGUAGE` and `LC_*`.
//! Anything else (`PATH`, `LD_PRELOAD`, `BASH_ENV`, `DYLD_INSERT_LIBRARIES`...)
//! changes what a restricted command actually executes, so it takes an explicit
//! opt-in in the config:
//!
//! ```toml
//! [server]
//! client_env = true                  # accept everything (the behaviour before the allow-list)
//! # client_env = false               # accept nothing
//! # client_env = ["TERM", "LC_*", "EDITOR"]   # exact names, or a prefix ending in `*`
//! ```
//!
//! Absent: the default list. A list REPLACES the default; it is not merged with it.

use serde::Deserialize;
use std::collections::HashMap;

/// Most variables taken from one `Open`.
pub const MAX_ENV_VARS: usize = 64;
/// Largest accepted value, in bytes.
pub const MAX_ENV_VALUE_BYTES: usize = 4096;

/// The names accepted when `client_env` is not set.
pub const DEFAULT_CLIENT_ENV: &[&str] = &["TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_*"];

/// The `client_env` config value as written.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ClientEnvSetting {
    /// `true` accepts every variable, `false` none.
    All(bool),
    /// Exact names, or prefixes ending in `*`.
    Names(Vec<String>),
}

/// What the server does with `Open.env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEnvPolicy {
    Everything,
    Nothing,
    Names(Vec<String>),
}

impl Default for ClientEnvPolicy {
    fn default() -> Self {
        Self::Names(DEFAULT_CLIENT_ENV.iter().map(|s| s.to_string()).collect())
    }
}

impl ClientEnvPolicy {
    pub fn from_setting(setting: Option<&ClientEnvSetting>) -> Result<Self, String> {
        match setting {
            None => Ok(Self::default()),
            Some(ClientEnvSetting::All(true)) => Ok(Self::Everything),
            Some(ClientEnvSetting::All(false)) => Ok(Self::Nothing),
            Some(ClientEnvSetting::Names(names)) => {
                if names.iter().any(|n| n.is_empty()) {
                    return Err("[server] client_env: list entries must be non-empty".into());
                }
                Ok(Self::Names(names.clone()))
            }
        }
    }

    fn allows(&self, name: &str) -> bool {
        match self {
            Self::Everything => true,
            Self::Nothing => false,
            Self::Names(patterns) => patterns.iter().any(|p| match p.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => p == name,
            }),
        }
    }

    /// Keep only what this policy accepts and what is well formed. `None` when
    /// nothing is left.
    pub fn filter(&self, requested: Option<&HashMap<String, String>>) -> Option<HashMap<String, String>> {
        let requested = requested?;
        let mut out = HashMap::new();
        for (seen, (name, value)) in requested.iter().enumerate() {
            if seen >= MAX_ENV_VARS {
                break;
            }
            if !valid_name(name)
                || value.len() > MAX_ENV_VALUE_BYTES
                || value.contains('\0')
                || !self.allows(name)
            {
                continue;
            }
            out.insert(name.clone(), value.clone());
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn keys(m: Option<HashMap<String, String>>) -> Vec<String> {
        let mut k: Vec<_> = m.unwrap_or_default().into_keys().collect();
        k.sort();
        k
    }

    #[test]
    fn the_default_list_takes_locale_and_terminal_names_only() {
        let p = ClientEnvPolicy::default();
        let got = p.filter(Some(&env(&[
            ("TERM", "xterm"),
            ("COLORTERM", "truecolor"),
            ("LANG", "C"),
            ("LANGUAGE", "en"),
            ("LC_ALL", "C"),
            ("LC_CTYPE", "C"),
            ("PATH", "/tmp/evil"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib"),
            ("BASH_ENV", "/tmp/x"),
            ("LCX", "no, not LC_*"),
        ])));
        assert_eq!(keys(got), ["COLORTERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TERM"]);
    }

    #[test]
    fn malformed_names_and_values_are_dropped_even_when_everything_is_accepted() {
        let big = "x".repeat(MAX_ENV_VALUE_BYTES + 1);
        let got = ClientEnvPolicy::Everything.filter(Some(&env(&[
            ("OK", "1"),
            ("1BAD", "1"),
            ("A=B", "1"),
            ("", "1"),
            ("HAS_NUL", "a\0b"),
            ("BIG", big.as_str()),
        ])));
        assert_eq!(keys(got), ["OK"]);
    }

    #[test]
    fn at_most_sixty_four_variables_are_taken() {
        let many: HashMap<String, String> = (0..200).map(|i| (format!("V{i}"), "1".into())).collect();
        let got = ClientEnvPolicy::Everything.filter(Some(&many)).unwrap();
        assert_eq!(got.len(), MAX_ENV_VARS);
    }

    #[test]
    fn nothing_accepts_nothing_and_a_list_replaces_the_default() {
        let req = env(&[("TERM", "xterm"), ("EDITOR", "vi"), ("LC_ALL", "C")]);
        assert_eq!(keys(ClientEnvPolicy::Nothing.filter(Some(&req))), Vec::<String>::new());
        let only = ClientEnvPolicy::from_setting(Some(&ClientEnvSetting::Names(vec!["EDITOR".into()]))).unwrap();
        assert_eq!(keys(only.filter(Some(&req))), ["EDITOR"]);
    }

    /// The exact line a deployment adds to get the behaviour from before the
    /// allow-list: `client_env = true` under `[server]`.
    #[test]
    fn the_config_values_parse() {
        #[derive(Deserialize)]
        struct Wrap {
            client_env: Option<ClientEnvSetting>,
        }
        let t: Wrap = toml::from_str("client_env = true").unwrap();
        assert_eq!(ClientEnvPolicy::from_setting(t.client_env.as_ref()).unwrap(), ClientEnvPolicy::Everything);
        let t: Wrap = toml::from_str("client_env = false").unwrap();
        assert_eq!(ClientEnvPolicy::from_setting(t.client_env.as_ref()).unwrap(), ClientEnvPolicy::Nothing);
        let t: Wrap = toml::from_str("client_env = [\"TERM\", \"LC_*\"]").unwrap();
        assert_eq!(
            ClientEnvPolicy::from_setting(t.client_env.as_ref()).unwrap(),
            ClientEnvPolicy::Names(vec!["TERM".into(), "LC_*".into()])
        );
        let t: Wrap = toml::from_str("").unwrap();
        assert_eq!(ClientEnvPolicy::from_setting(t.client_env.as_ref()).unwrap(), ClientEnvPolicy::default());
        assert!(toml::from_str::<Wrap>("client_env = \"all\"").is_err());
    }
}
