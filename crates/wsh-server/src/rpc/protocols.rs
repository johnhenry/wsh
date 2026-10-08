//! The built-in rpc protocols: `wsh-host` and `wsh-fs`.
//!
//! Method names, parameter names, result shapes, error codes and messages are
//! the JS server's (`src/server/rpc.mjs`).

use super::channel::RpcContext;
use super::fs::{FileAccess, FsError};
use super::{get, map, text, uint, RpcError, Value};
use std::sync::Arc;

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// What `host.info` reports.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub version: String,
    /// The `ServerHello.features` this connection was offered.
    pub features: Vec<String>,
    pub user: String,
    pub protocols: Vec<String>,
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Host(Arc<HostInfo>),
    Fs(FileAccess),
    /// Test-only methods exercising the engine (`slow`, `echo`, `burst`).
    #[cfg(test)]
    Test,
}

fn need_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    match get(params, key) {
        Some(Value::Text(s)) => Ok(s),
        _ => Err(RpcError::invalid_params(format!(
            "\"{key}\" (string) is required"
        ))),
    }
}

fn need_bytes<'a>(params: &'a Value, key: &str) -> Result<&'a [u8], RpcError> {
    match get(params, key) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(RpcError::invalid_params(format!(
            "\"{key}\" (byte string) is required"
        ))),
    }
}

/// `undefined`/`null` -> `None`; a non-negative safe integer -> `Some`; anything else is `illegal <what>`.
fn opt_uint(v: Option<&Value>, what: &str) -> Result<Option<u64>, FsError> {
    let f = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Integer(i)) => i128::from(*i) as f64,
        Some(Value::Float(f)) => *f,
        Some(_) => return Err(FsError::Invalid(format!("illegal {what}"))),
    };
    if !f.is_finite() || f.fract() != 0.0 || !(0.0..=MAX_SAFE_INTEGER).contains(&f) {
        return Err(FsError::Invalid(format!("illegal {what}")));
    }
    Ok(Some(f as u64))
}

impl Protocol {
    pub fn handles(&self, method: &str) -> bool {
        match self {
            Protocol::Host(_) => matches!(method, "host.info" | "host.ping"),
            Protocol::Fs(_) => matches!(
                method,
                "stat"
                    | "list"
                    | "read"
                    | "write"
                    | "upload"
                    | "download"
                    | "rename"
                    | "mkdir"
                    | "remove"
            ),
            #[cfg(test)]
            Protocol::Test => matches!(method, "slow" | "echo" | "burst" | "big"),
        }
    }

    pub async fn call(
        &self,
        method: &str,
        params: Value,
        ctx: &RpcContext,
    ) -> Result<Value, RpcError> {
        // `params ?? {}`
        let params = if matches!(params, Value::Null) {
            Value::Map(vec![])
        } else {
            params
        };
        match self {
            Protocol::Host(info) => host_call(info, method),
            Protocol::Fs(files) => fs_call(files, method, &params, ctx).await.map_err(|e| e.0),
            #[cfg(test)]
            Protocol::Test => test_call(method, &params, ctx).await,
        }
    }
}

fn host_call(info: &HostInfo, method: &str) -> Result<Value, RpcError> {
    match method {
        "host.info" => Ok(map([
            ("version", text(&info.version)),
            ("protocol", text("wsh-v1")),
            (
                "features",
                Value::Array(info.features.iter().map(|f| text(f)).collect()),
            ),
            ("hostFingerprint", Value::Null),
            ("user", text(&info.user)),
            (
                "rpc",
                map([
                    (
                        "protocols",
                        Value::Array(info.protocols.iter().map(|p| text(p)).collect()),
                    ),
                    ("maxMessageBytes", uint(info.max_message_bytes as u64)),
                ]),
            ),
        ])),
        "host.ping" => {
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Ok(map([("time", uint(ms))]))
        }
        _ => Err(RpcError::new(
            super::code::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )),
    }
}

/// Newtype so `?` can lift both `RpcError` and `FsError` into one return type.
struct Failure(RpcError);
impl From<RpcError> for Failure {
    fn from(e: RpcError) -> Self {
        Failure(e)
    }
}
impl From<FsError> for Failure {
    fn from(e: FsError) -> Self {
        Failure(e.into_rpc())
    }
}

async fn fs_call(
    files: &FileAccess,
    method: &str,
    p: &Value,
    ctx: &RpcContext,
) -> Result<Value, Failure> {
    match method {
        "stat" => Ok(files.stat(need_string(p, "path")?).await?),
        "list" => {
            let path = match get(p, "path") {
                Some(Value::Text(s)) => s.as_str(),
                _ => "/",
            };
            let entries = files.list(path).await?;
            Ok(map([
                ("path", text(if path.is_empty() { "/" } else { path })),
                ("entries", Value::Array(entries)),
            ]))
        }
        "mkdir" => {
            files.mkdir(need_string(p, "path")?).await?;
            Ok(Value::Map(vec![]))
        }
        "remove" => {
            let path = need_string(p, "path")?;
            files.remove(path).await?;
            Ok(map([("removed", text(path))]))
        }
        "rename" => {
            let path = need_string(p, "path")?;
            let new_path = need_string(p, "newPath")?;
            files.rename(path, new_path).await?;
            Ok(map([("renamed", text(path)), ("to", text(new_path))]))
        }
        "write" => {
            let path = need_string(p, "path")?;
            let data = need_bytes(p, "data")?;
            let offset = opt_uint(get(p, "offset"), "offset")?;
            files.write_at(path, data, offset, false).await?;
            Ok(map([("written", uint(data.len() as u64))]))
        }
        // upload: the chunk-friendly write. offset omitted/0 creates or truncates the file; offset > 0 continues it in place.
        "upload" => {
            let data = need_bytes(p, "data")?;
            let offset = match opt_uint(get(p, "offset"), "offset") {
                Ok(o) => o.unwrap_or(0),
                Err(e) => return Err(e.into()),
            };
            let path = need_string(p, "path")?;
            if offset == 0 {
                files.write_at(path, data, None, true).await?;
            } else {
                files.write_at(path, data, Some(offset), false).await?;
            }
            Ok(map([
                ("written", uint(data.len() as u64)),
                ("offset", uint(offset)),
            ]))
        }
        // read / download: chunks arrive as `$/progress`, the result is a summary.
        "read" | "download" => {
            let path = need_string(p, "path")?;
            let (offset, length) = if method == "read" {
                (get(p, "offset"), get(p, "length"))
            } else {
                (None, None)
            };
            let chunk_bytes = ctx
                .max_message_bytes()
                .saturating_sub(512)
                .min(64 * 1024)
                .max(64);
            // Validation order of openRange: offset, then length.
            let offset = opt_uint(offset, "offset")?;
            let length = opt_uint(length, "length")?;
            let mut range = files.open_range(path, offset, length, chunk_bytes).await?;
            let mut sent: u64 = 0;
            while let Some(chunk) = range.next_chunk().await? {
                if ctx.aborted() {
                    break;
                }
                let n = chunk.len() as u64;
                ctx.progress(Value::Bytes(chunk)).await?;
                sent += n;
            }
            Ok(map([
                ("size", uint(range.size)),
                ("offset", uint(range.offset)),
                ("length", uint(sent)),
                ("eof", Value::Bool(range.offset + sent >= range.size)),
            ]))
        }
        _ => Err(RpcError::new(
            super::code::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )
        .into()),
    }
}

#[cfg(test)]
async fn test_call(method: &str, p: &Value, ctx: &RpcContext) -> Result<Value, RpcError> {
    match method {
        "echo" => Ok(p.clone()),
        // a result of `bytes` bytes, however small the request
        "big" => {
            let n = match get(p, "bytes") {
                Some(Value::Integer(i)) => i128::from(*i) as usize,
                _ => 0,
            };
            Ok(Value::Bytes(vec![9; n]))
        }
        // waits until cancelled (or the channel closes), then reports it was aborted
        "slow" => {
            ctx.cancelled().await;
            Ok(Value::Text("aborted".into()))
        }
        // N progress notifications of M bytes each
        "burst" => {
            let n = match get(p, "n") {
                Some(Value::Integer(i)) => i128::from(*i) as usize,
                _ => 1,
            };
            let m = match get(p, "bytes") {
                Some(Value::Integer(i)) => i128::from(*i) as usize,
                _ => 1,
            };
            for _ in 0..n {
                ctx.progress(Value::Bytes(vec![1; m])).await?;
            }
            Ok(map([("sent", uint(n as u64))]))
        }
        _ => Err(RpcError::new(
            super::code::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )),
    }
}
