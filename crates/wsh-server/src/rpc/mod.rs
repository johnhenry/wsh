//! Typed RPC channels (wsh #85 / #86): `Open { kind: "rpc", command: <protocol> }`.
//!
//! An `rpc` channel is an ordinary QMux stream whose payload is a CBOR
//! sequence (RFC 8742) of JSON-RPC 2.0 messages. This is the Rust twin of the
//! JS server's `src/rpc.mjs` + `src/server/rpc.mjs` + `src/server/fs.mjs`, and
//! it must stay behaviourally identical: same feature advertisement, same
//! error codes and messages, same `wsh-fs` confinement rules.
//!
//! Layout:
//! - [`seq`]       incremental CBOR-sequence decoder with a size bound
//! - [`channel`]   transport-free JSON-RPC 2.0 engine (`$/cancel`, `$/progress`)
//! - [`fs`]        confined file access (`wsh-fs`)
//! - [`protocols`] the `wsh-host` and `wsh-fs` protocol handlers
//! - [`session`]   per-connection glue binding channels to QMux streams

pub mod channel;
pub mod fs;
pub mod protocols;
pub mod seq;
pub mod session;

use ciborium::value::Value;

/// `ServerHello` feature: the host serves `rpc` sessions.
pub const RPC_FEATURE: &str = "rpc";
/// `ServerHello` feature prefix: one `rpc-protocol:<name>` per protocol.
pub const RPC_PROTOCOL_PREFIX: &str = "rpc-protocol:";
/// `ServerHello` feature prefix: `rpc-max-message:<bytes>`.
pub const RPC_MAX_MESSAGE_PREFIX: &str = "rpc-max-message:";
/// Largest message when the operator does not say (1 MiB).
pub const RPC_DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;
/// Concurrent inbound requests per channel before `-32002`.
pub const RPC_DEFAULT_MAX_INFLIGHT: usize = 64;
/// Smallest message limit a host may be configured with.
pub const RPC_MIN_MAX_MESSAGE: usize = 256;

pub const WSH_HOST: &str = "wsh-host";
pub const WSH_FS: &str = "wsh-fs";

/// JSON-RPC's reserved codes plus wsh's.
pub mod code {
    pub const PARSE: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;
    pub const UNSUPPORTED_PROTOCOL: i64 = -32000;
    pub const CANCELLED: i64 = -32001;
    pub const STREAM_LIMIT: i64 = -32002;
    pub const UNAUTHORIZED: i64 = -32003;
}

/// Resolved rpc settings of a running server (from `[rpc]` in the config).
#[derive(Debug, Clone)]
pub struct RpcSettings {
    pub max_message_bytes: usize,
    pub max_inflight: usize,
    /// `wsh-fs` is offered only when a file root is configured.
    pub fs: Option<fs::FileAccess>,
}

impl RpcSettings {
    /// Protocol names in advertisement order.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut p = vec![WSH_HOST];
        if self.fs.is_some() {
            p.push(WSH_FS);
        }
        p
    }

    /// The `ServerHello.features` entries for rpc.
    pub fn features(&self) -> Vec<String> {
        let mut f = vec![RPC_FEATURE.to_string()];
        f.extend(
            self.protocols()
                .iter()
                .map(|n| format!("{RPC_PROTOCOL_PREFIX}{n}")),
        );
        f.push(format!(
            "{RPC_MAX_MESSAGE_PREFIX}{}",
            self.max_message_bytes
        ));
        f
    }
}

/// A protocol name travels in a feature string and in `Open.command`: keep it boring.
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
pub fn valid_protocol_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A JSON-RPC error: what a handler returns to answer with an error response.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// `data: { reason: <reason> }`
    pub fn with_reason(code: i64, message: impl Into<String>, reason: &str) -> Self {
        Self::with_data(code, message, map([("reason", text(reason))]))
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_PARAMS, message)
    }

    pub fn too_large(what: &str, size: usize, max: usize) -> Self {
        Self::with_reason(
            code::INVALID_REQUEST,
            format!("{what} of {size} bytes exceeds the {max} byte rpc message limit"),
            "message-too-large",
        )
    }

    /// The `error` member of a response.
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (text("code"), Value::Integer(self.code.into())),
            (text("message"), text(&self.message)),
        ];
        if let Some(d) = &self.data {
            entries.push((text("data"), d.clone()));
        }
        Value::Map(entries)
    }
}

// ── Value helpers ─────────────────────────────────────────────────────

pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub fn int(n: i64) -> Value {
    Value::Integer(n.into())
}

pub fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}

/// Build a map from `(key, value)` pairs.
pub fn map<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

/// Look up a text key in a CBOR map.
pub fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// A JSON-RPC id (`string` or finite `number`), normalised for use as a map key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdKey {
    Str(String),
    /// The `f64` bit pattern: JS has one number type, so `1` and `1.0` are one id.
    Num(u64),
}

/// `Some(key)` when `v` is a valid JSON-RPC id.
pub fn id_key(v: &Value) -> Option<IdKey> {
    match v {
        Value::Text(s) => Some(IdKey::Str(s.clone())),
        Value::Integer(i) => {
            let n = i128::from(*i) as f64;
            Some(IdKey::Num(normalise(n).to_bits()))
        }
        Value::Float(f) if f.is_finite() => Some(IdKey::Num(normalise(*f).to_bits())),
        _ => None,
    }
}

fn normalise(f: f64) -> f64 {
    if f == 0.0 {
        0.0
    } else {
        f
    }
}

/// How JS prints an id inside a message (`${id}`).
pub fn id_display(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Integer(i) => i128::from(*i).to_string(),
        Value::Float(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", *f as i128),
        Value::Float(f) => f.to_string(),
        _ => String::new(),
    }
}
