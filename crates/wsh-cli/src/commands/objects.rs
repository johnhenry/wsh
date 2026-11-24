//! `wsh --sealed [--via RELAY] objects [user@]host <operation>` -- scripting and inspection of a host's remote
//! objects (`wsh-objects`, `spec/objects.md`), JSON on stdout. The client is `wsh_client::objects`.
//!
//! Operations: `roots`, `describe ROOT[.path]`, `get ROOT.path`, `call ROOT.path [JSON args...]`,
//! `construct ROOT.path [JSON args...]`, `set ROOT.path JSON`, `snapshot ROOT.path`, `watch ROOT.path@event`
//! (one JSON value per line), and `session` (JSON lines on stdin, one answer per line, one connection: the way to
//! hold a handle across calls).
//!
//! Rules:
//! - **Sealed only.** Without `--sealed` it refuses to start (exit 2): the path, the arguments and the values are
//!   the content a relay must not see, and a host that serves objects serves them sealed.
//! - **Stdout is JSON** and nothing else. Plain data is printed as the JSON it is. What is not plain JSON is printed
//!   as a named object: bytes `{"$bytes":"<base64>"}`, what the host could not clone `{"$nonValue":{"kind":..}}`,
//!   a handle `{"$handle":{..}}`. (A page can make plain data that looks like these: this is an inspection format.)
//! - **Text from the host is never interpreted.** Every string it supplies -- names, strings, previews, error
//!   messages -- is printed as a JSON string, with every control character, every C1 control, and the line, paragraph
//!   and bidirectional-text separators written as `\uXXXX`, so nothing it says can reach the terminal as itself.
//!   Diagnostics go to stderr, the same way.
//! - **Exit status**: 0 done; 1 any other failure (connection lost, the operation failed); 2 it could not start
//!   (usage, not sealed); 3 the host refused (its rules, a key capability, a bound); 4 not found (a root, a path, a
//!   handle); 5 unsupported (the host does not state the channel or the feature).

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

use serde_json::Value as Json;
use tokio::io::{AsyncBufReadExt, BufReader};
use wsh_client::objects::{
    Chain, Description, ErrorKind, Event, Handle, ObjectsClient, ObjectsError, OpenOptions, Path,
    Reply, SnapshotOptions, SubscribeOptions, Target, Value,
};

use crate::commands::common::{
    connect_client_with, identity_policy, redact_rendezvous, resolve_target,
};

/// Longest line `session` reads from stdin.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// What to do, as the command line spelled it.
#[derive(Debug, Clone)]
pub enum Op {
    Roots,
    Describe {
        path: String,
    },
    Get {
        path: String,
    },
    Call {
        path: String,
        args: Vec<String>,
    },
    Construct {
        path: String,
        args: Vec<String>,
    },
    Set {
        path: String,
        value: String,
    },
    Snapshot {
        path: String,
        depth: Option<u32>,
        max_bytes: Option<u64>,
    },
    Watch {
        spec: String,
        fields: Vec<String>,
        count: Option<u64>,
        capacity: usize,
    },
    Session,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub target: String,
    pub port: u16,
    pub transport: Option<String>,
    pub identity: String,
    pub host_key: Option<String>,
    pub timeout: Duration,
    pub op: Op,
}

// ── Rendering ───────────────────────────────────────────────────────────────────────────────────────────────────────

/// A string as a JSON string. Beyond JSON's own escapes, every character a terminal could act on is a `\uXXXX`.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_unsafe(c) => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A character that must not reach a terminal as itself: C0 and C1 controls, DEL, the line and paragraph
/// separators, the bidirectional-text controls, the byte order mark.
fn is_unsafe(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{61c}' | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn float(f: f64) -> String {
    if f.is_finite() {
        // JSON's number grammar; an integral float keeps its point so it reads back as a float
        let s = format!("{f}");
        if s.contains(['.', 'e', 'E']) {
            s
        } else {
            format!("{s}.0")
        }
    } else {
        // JSON has no NaN or infinity: say so by name rather than make a number up
        format!(
            "{{\"$nonValue\":{{\"kind\":\"number\",\"text\":{}}}}}",
            json_string(&f.to_string())
        )
    }
}

/// Plain data as JSON text (bytes as `{"$bytes":".."}`).
pub fn render_value(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) => out.push_str(&float(*f)),
        Value::Text(s) => out.push_str(&json_string(s)),
        Value::Bytes(b) => {
            out.push_str("{\"$bytes\":");
            out.push_str(&json_string(&base64(b)));
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k));
                out.push(':');
                write_value(x, out);
            }
            out.push('}');
        }
    }
}

fn opt_string(label: &str, v: Option<&str>, out: &mut Vec<String>) {
    if let Some(v) = v {
        out.push(format!("\"{label}\":{}", json_string(v)));
    }
}

/// What a request came to, as JSON text. `alias` names a handle in a `session` (a one-shot has none).
pub fn render_reply(reply: &Reply, alias: Option<&str>) -> String {
    match reply {
        Reply::Value(v) => render_value(v),
        Reply::NonValue(n) => {
            let mut parts = vec![format!("\"kind\":{}", json_string(&n.kind))];
            opt_string("type", n.type_name.as_deref(), &mut parts);
            opt_string("text", n.text.as_deref(), &mut parts);
            format!("{{\"$nonValue\":{{{}}}}}", parts.join(","))
        }
        Reply::Handle(h) => render_handle(h, alias),
    }
}

fn render_handle(h: &Handle, alias: Option<&str>) -> String {
    let mut parts = Vec::new();
    opt_string("id", alias, &mut parts);
    parts.push(format!("\"kind\":{}", json_string(h.kind())));
    opt_string("type", h.type_name(), &mut parts);
    let keys: Vec<String> = h.preview_keys().iter().map(|k| json_string(k)).collect();
    parts.push(format!("\"preview\":[{}]", keys.join(",")));
    format!("{{\"$handle\":{{{}}}}}", parts.join(","))
}

fn render_description(d: &Description) -> String {
    let keys: Vec<String> = d
        .keys
        .iter()
        .map(|k| {
            format!(
                "{{\"key\":{},\"type\":{},\"own\":{}}}",
                json_string(&k.key),
                json_string(&k.type_name),
                k.own
            )
        })
        .collect();
    format!(
        "{{\"type\":{},\"keys\":[{}],\"truncated\":{}}}",
        json_string(&d.type_name),
        keys.join(","),
        d.truncated
    )
}

fn render_event(e: &Event) -> String {
    format!(
        "{{\"seq\":{},\"dropped\":{},\"dropped_here\":{},\"data\":{}}}",
        e.seq,
        e.dropped_by_host,
        e.dropped_here,
        render_value(&e.data)
    )
}

fn kind_word(k: ErrorKind) -> &'static str {
    match k {
        ErrorKind::Refused => "refused",
        ErrorKind::Limit => "limit",
        ErrorKind::Invalid => "invalid",
        ErrorKind::NotFound => "not-found",
        ErrorKind::Failed => "failed",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Closed => "closed",
        ErrorKind::Protocol => "protocol",
    }
}

/// The exit status of a failed operation.
pub fn exit_code(e: &ObjectsError) -> i32 {
    match e.kind {
        ErrorKind::Refused | ErrorKind::Limit => 3,
        ErrorKind::NotFound => 4,
        ErrorKind::Unsupported => 5,
        ErrorKind::Invalid => 2,
        ErrorKind::Failed | ErrorKind::Closed | ErrorKind::Protocol => 1,
    }
}

/// An error as one line for stderr: the rule that spoke, and the text as a JSON string.
pub fn render_error_line(e: &ObjectsError) -> String {
    let reason = e
        .reason
        .as_deref()
        .map(|r| format!(" ({})", json_string(r).trim_matches('"')))
        .unwrap_or_default();
    format!(
        "wsh objects: {}{reason}: {}",
        kind_word(e.kind),
        json_string(&e.message)
    )
}

fn render_error_json(e: &ObjectsError) -> String {
    let mut parts = vec![format!("\"kind\":{}", json_string(kind_word(e.kind)))];
    opt_string("reason", e.reason.as_deref(), &mut parts);
    parts.push(format!("\"message\":{}", json_string(&e.message)));
    format!("{{{}}}", parts.join(","))
}

fn out(line: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

fn note(line: &str) {
    eprintln!("{line}");
}

// ── Arguments ───────────────────────────────────────────────────────────────────────────────────────────────────────

/// `ROOT.a.b` as the root and the path under it.
pub fn split_root(text: &str) -> Result<(String, Path), String> {
    let mut it = text.split('.');
    let root = it.next().unwrap_or("");
    if root.is_empty() {
        return Err(format!(
            "{text:?}: a path starts with the root's name (ROOT.a.b)"
        ));
    }
    let rest: Vec<String> = it.map(str::to_string).collect();
    if rest.iter().any(String::is_empty) {
        return Err(format!("{text:?}: an empty path segment"));
    }
    Ok((root.to_string(), Path::from(rest)))
}

fn json_arg(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Json>(text)
        .map(Value::from)
        .map_err(|e| format!("{text:?} is not JSON: {e}"))
}

// ── Running ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/// `wsh objects`: never returns; the process exits with the status described at the top.
pub async fn run(opts: Options) -> anyhow::Result<()> {
    let code = start(opts).await;
    std::process::exit(code);
}

async fn start(opts: Options) -> i32 {
    if !identity_policy().sealed_session {
        eprintln!(
            "wsh objects: needs --sealed (wsh --sealed [--via RELAY] objects ...): the paths and values it carries are \
             what a relay must not see"
        );
        return 2;
    }
    // Arguments are parsed before anything is dialled.
    let plan = match Plan::new(&opts.op) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("wsh objects: {e}");
            return 2;
        }
    };
    let resolved = match resolve_target(&opts.target, opts.port, opts.transport.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wsh objects: {e:#}");
            return 2;
        }
    };
    let host_key = opts.host_key.clone();
    let secs = opts.timeout.as_secs().max(1);
    let client = match connect_client_with(&resolved, &opts.identity, move |c| {
        c.expect_host_key = host_key;
        c.timeout_secs = secs;
    })
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "wsh objects: cannot connect to {}: {}",
                redact_rendezvous(&resolved.url),
                json_string(&format!("{e:#}"))
            );
            return 1;
        }
    };
    if !client.session_sealed() {
        eprintln!("wsh objects: the session is not sealed: refusing to carry objects over it");
        let _ = client.disconnect().await;
        return 2;
    }
    let objects = match ObjectsClient::open_with(
        &client,
        OpenOptions {
            timeout: opts.timeout,
        },
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", render_error_line(&e));
            let code = exit_code(&e);
            let _ = client.disconnect().await;
            return code;
        }
    };
    let code = match plan.execute(&objects).await {
        Ok(()) => 0,
        Err(Stop::Error(e)) => {
            eprintln!("{}", render_error_line(&e));
            exit_code(&e)
        }
        Err(Stop::Usage(m)) => {
            eprintln!("wsh objects: {m}");
            2
        }
    };
    objects.close().await;
    let _ = client.disconnect().await;
    code
}

enum Stop {
    Error(ObjectsError),
    Usage(String),
}

impl From<ObjectsError> for Stop {
    fn from(e: ObjectsError) -> Self {
        Stop::Error(e)
    }
}

/// An operation with its arguments parsed.
enum Plan {
    Roots,
    Describe(String, Path),
    Get(String, Path),
    Call(String, Path, Vec<Value>, bool),
    Set(String, Path, Value),
    Snapshot(String, Path, SnapshotOptions),
    Watch {
        root: String,
        path: Path,
        event: String,
        fields: Vec<String>,
        count: Option<u64>,
        capacity: usize,
    },
    Session,
}

impl Plan {
    fn new(op: &Op) -> Result<Plan, String> {
        Ok(match op {
            Op::Roots => Plan::Roots,
            Op::Describe { path } => {
                let (r, p) = split_root(path)?;
                Plan::Describe(r, p)
            }
            Op::Get { path } => {
                let (r, p) = split_root(path)?;
                Plan::Get(r, p)
            }
            Op::Call { path, args } | Op::Construct { path, args } => {
                let (r, p) = split_root(path)?;
                if p.is_empty() {
                    return Err(format!(
                        "{path:?}: name the method after the root (ROOT.obj.method)"
                    ));
                }
                let args = args
                    .iter()
                    .map(|a| json_arg(a))
                    .collect::<Result<Vec<_>, _>>()?;
                Plan::Call(r, p, args, matches!(op, Op::Construct { .. }))
            }
            Op::Set { path, value } => {
                let (r, p) = split_root(path)?;
                if p.is_empty() {
                    return Err(format!(
                        "{path:?}: name the member after the root (ROOT.obj.member)"
                    ));
                }
                Plan::Set(r, p, json_arg(value)?)
            }
            Op::Snapshot {
                path,
                depth,
                max_bytes,
            } => {
                let (r, p) = split_root(path)?;
                Plan::Snapshot(
                    r,
                    p,
                    SnapshotOptions {
                        depth: *depth,
                        max_bytes: *max_bytes,
                    },
                )
            }
            Op::Watch {
                spec,
                fields,
                count,
                capacity,
            } => {
                let (source, event) = spec
                    .split_once('@')
                    .ok_or_else(|| format!("{spec:?}: say the event (ROOT.path@event)"))?;
                if event.is_empty() {
                    return Err(format!("{spec:?}: say the event (ROOT.path@event)"));
                }
                let (root, path) = split_root(source)?;
                Plan::Watch {
                    root,
                    path,
                    event: event.to_string(),
                    fields: fields.clone(),
                    count: *count,
                    capacity: *capacity,
                }
            }
            Op::Session => Plan::Session,
        })
    }

    async fn execute(self, objects: &ObjectsClient) -> Result<(), Stop> {
        match self {
            Plan::Roots => {
                let roots: Vec<String> = objects.roots().iter().map(|r| json_string(r)).collect();
                let features: Vec<String> =
                    objects.features().iter().map(|r| json_string(r)).collect();
                out(&format!(
                    "{{\"roots\":[{}],\"features\":[{}]}}",
                    roots.join(","),
                    features.join(",")
                ));
            }
            Plan::Describe(root, path) => {
                out(&render_description(
                    &objects.root(&root)?.describe(path).await?,
                ));
            }
            Plan::Get(root, path) => {
                let reply = objects.root(&root)?.get(path).await?;
                out(&render_reply(&reply, None));
            }
            Plan::Call(root, path, args, construct) => {
                let target = objects.root(&root)?;
                let chain = if construct {
                    Chain::new().construct(path, args)
                } else {
                    Chain::new().call(path, args)
                };
                out(&render_reply(&target.resolve(chain).await?, None));
            }
            Plan::Set(root, path, value) => {
                objects.root(&root)?.set(path, value).await?;
                out("{\"ok\":true}");
            }
            Plan::Snapshot(root, path, options) => {
                let snapshot = objects.root(&root)?.snapshot(path, options).await?;
                out(&render_reply(&snapshot.reply, None));
                if snapshot.truncated {
                    note("wsh objects: the snapshot was cut: a subtree deeper than the depth is null");
                }
            }
            Plan::Watch {
                root,
                path,
                event,
                fields,
                count,
                capacity,
            } => {
                let target = objects.root(&root)?;
                let mut sub = target
                    .subscribe(path, &event, SubscribeOptions { capacity, fields })
                    .await?;
                note("wsh objects: subscribed");
                let mut seen = 0u64;
                loop {
                    let next = tokio::select! {
                        e = sub.recv() => e,
                        _ = shutdown_signal() => return Ok(()),
                    };
                    let Some(e) = next else {
                        let why = objects
                            .closing_reason()
                            .map(|r| format!(" (the host said {})", json_string(&r)))
                            .unwrap_or_default();
                        note(&format!("wsh objects: the channel ended{why}"));
                        return Err(Stop::Error(ObjectsError::from_rpc(
                            -32000,
                            "the channel ended".into(),
                            Some(Value::Object(vec![(
                                "reason".into(),
                                Value::Text("closed".into()),
                            )])),
                        )));
                    };
                    out(&render_event(&e));
                    seen += 1;
                    if count.is_some_and(|n| seen >= n) {
                        let _ = sub.unsubscribe().await;
                        return Ok(());
                    }
                }
            }
            Plan::Session => session(objects).await?,
        }
        Ok(())
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

// ── session: JSON lines on stdin ────────────────────────────────────────────────────────────────────────────────────

/// One connection, many requests, one answer line each (in order). A request is a JSON object:
///
/// - `{"op":"get","path":"ROOT.a.b"}`, `{"op":"call","path":"ROOT.a.f","args":[..]}`, `{"op":"construct",..}`,
///   `{"op":"set","path":"ROOT.a.b","value":..}`, `{"op":"snapshot","path":..,"depth":N,"maxBytes":N}`,
///   `{"op":"describe","path":..}`, `{"op":"roots"}`;
/// - through a handle the host returned (its `id` in the `$handle` answer): the same with `"handle":"h1"` and a
///   `path` relative to it (`""` is the handle itself); `{"op":"release","handle":"h1"}` gives it back.
///
/// The answer is `{"ok":true,"result":..}` or `{"ok":false,"error":{"kind","reason","message"}}`.
async fn session(objects: &ObjectsClient) -> Result<(), Stop> {
    let mut handles: HashMap<String, Handle> = HashMap::new();
    let mut next_alias = 1u64;
    let mut lines = BufReader::new(tokio::io::stdin());
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = tokio::select! {
            r = read_line(&mut lines, &mut buf) => r,
            _ = shutdown_signal() => return Ok(()),
        };
        match n {
            Ok(Some(true)) => {}
            Ok(Some(false)) => {
                out(&format!(
                    "{{\"ok\":false,\"error\":{{\"kind\":\"invalid\",\"reason\":\"bad-request\",\"message\":{}}}}}",
                    json_string(&format!("a request line is at most {MAX_LINE_BYTES} bytes"))
                ));
                continue;
            }
            _ => return Ok(()),
        }
        let text = String::from_utf8_lossy(&buf);
        if text.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Json>(&text) {
            Ok(request) => match step(objects, &mut handles, &mut next_alias, &request).await {
                Ok(result) => format!("{{\"ok\":true,\"result\":{result}}}"),
                Err(e) => format!("{{\"ok\":false,\"error\":{}}}", render_error_json(&e)),
            },
            Err(e) => format!(
                "{{\"ok\":false,\"error\":{{\"kind\":\"invalid\",\"reason\":\"bad-request\",\"message\":{}}}}}",
                json_string(&format!("not JSON: {e}"))
            ),
        };
        out(&answer);
    }
}

/// A line, bounded: `Some(true)` read, `Some(false)` too long (skipped), `None` end of input.
async fn read_line(
    reader: &mut BufReader<tokio::io::Stdin>,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<bool>> {
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() && !too_long {
                None
            } else {
                Some(!too_long)
            });
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if !too_long {
            buf.extend_from_slice(&available[..take]);
            if buf.len() > MAX_LINE_BYTES {
                too_long = true;
                buf.clear();
            }
        }
        reader.consume(take);
        if done {
            return Ok(Some(!too_long));
        }
    }
}

fn bad(message: impl Into<String>) -> ObjectsError {
    ObjectsError::from_rpc(
        -32602,
        message.into(),
        Some(Value::Object(vec![(
            "reason".into(),
            Value::Text("bad-request".into()),
        )])),
    )
}

async fn step(
    objects: &ObjectsClient,
    handles: &mut HashMap<String, Handle>,
    next_alias: &mut u64,
    request: &Json,
) -> Result<String, ObjectsError> {
    let field = |name: &str| request.get(name);
    let op = field("op")
        .and_then(Json::as_str)
        .ok_or_else(|| bad("a request has an \"op\""))?;
    if op == "roots" {
        let roots: Vec<String> = objects.roots().iter().map(|r| json_string(r)).collect();
        return Ok(format!("{{\"roots\":[{}]}}", roots.join(",")));
    }
    if op == "release" {
        let id = field("handle")
            .and_then(Json::as_str)
            .ok_or_else(|| bad("release needs a \"handle\""))?;
        let handle = handles
            .remove(id)
            .ok_or_else(|| bad("no such handle in this session"))?;
        handle.release().await?;
        return Ok("{\"ok\":true}".into());
    }
    // Where it starts, and the path below that.
    let path_text = field("path").and_then(Json::as_str).unwrap_or("");
    let (target, path): (Target, Path) = match field("handle") {
        Some(h) => {
            let id = h
                .as_str()
                .ok_or_else(|| bad("\"handle\" is the id a $handle answer gave"))?;
            let handle = handles
                .get(id)
                .ok_or_else(|| bad("no such handle in this session"))?;
            (handle.target(), Path::parse(path_text))
        }
        None => {
            let (root, path) = split_root(path_text).map_err(bad)?;
            (objects.root(&root)?, path)
        }
    };
    let args = || -> Result<Vec<Value>, ObjectsError> {
        match field("args") {
            None => Ok(Vec::new()),
            Some(Json::Array(a)) => Ok(a.iter().cloned().map(Value::from).collect()),
            Some(_) => Err(bad("\"args\" is an array")),
        }
    };
    let reply = match op {
        "get" => target.get(path).await?,
        "call" => target.resolve(Chain::new().call(path, args()?)).await?,
        "construct" => {
            target
                .resolve(Chain::new().construct(path, args()?))
                .await?
        }
        "set" => {
            let value = field("value")
                .cloned()
                .ok_or_else(|| bad("set needs a \"value\""))?;
            target.set(path, Value::from(value)).await?;
            return Ok("{\"ok\":true}".into());
        }
        "describe" => return Ok(render_description(&target.describe(path).await?)),
        "snapshot" => {
            let options = SnapshotOptions {
                depth: field("depth").and_then(Json::as_u64).map(|d| d as u32),
                max_bytes: field("maxBytes").and_then(Json::as_u64),
            };
            target.snapshot(path, options).await?.reply
        }
        other => {
            return Err(bad(format!(
                "no such op: {} (roots, get, call, construct, set, describe, snapshot, release)",
                json_string(other)
            )))
        }
    };
    Ok(match reply {
        Reply::Handle(h) => {
            let alias = format!("h{next_alias}");
            *next_alias += 1;
            let rendered = render_handle(&h, Some(&alias));
            handles.insert(alias, h);
            rendered
        }
        other => render_reply(&other, None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsh_client::objects::NonValue;

    #[test]
    fn a_string_is_json_with_every_control_written_out() {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        // ESC, a CSI as a C1 control, DEL, NUL, the line separator, a bidi override, the byte order mark
        let hostile = "\u{1b}[31m\u{9b}2J\u{7f}\u{0}\u{2028}\u{202e}\u{feff}";
        let shown = json_string(hostile);
        for c in shown.chars() {
            assert!(
                !c.is_control() && !is_unsafe(c),
                "{c:?} reached the output raw: {shown}"
            );
        }
        assert!(
            shown.contains("\\u001b[31m") && shown.contains("\\u009b") && shown.contains("\\u202e")
        );
        // text that is only text stays as it is
        assert_eq!(json_string("héllo \u{1F600}"), "\"héllo \u{1F600}\"");
    }

    #[test]
    fn every_char_below_the_c1_range_that_a_terminal_acts_on_is_caught() {
        for c in ('\u{0}'..='\u{9f}').chain([
            '\u{2028}', '\u{2029}', '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}',
        ]) {
            let shown = json_string(&c.to_string());
            if c == ' ' || c.is_ascii_graphic() {
                continue;
            }
            assert!(
                shown.chars().all(|x| x.is_ascii_graphic() || x == ' '),
                "{:?} -> {shown}",
                c
            );
        }
    }

    #[test]
    fn plain_data_is_json_and_bytes_and_nonvalues_are_named() {
        let v = Value::Object(vec![
            ("n".into(), Value::Int(-1)),
            ("f".into(), Value::Float(2.0)),
            ("k\u{1b}".into(), Value::Text("v\u{1b}".into())),
            ("b".into(), Value::Bytes(vec![1, 2, 3, 4])),
            (
                "a".into(),
                Value::Array(vec![Value::Null, Value::Bool(true)]),
            ),
        ]);
        assert_eq!(
            render_value(&v),
            "{\"n\":-1,\"f\":2.0,\"k\\u001b\":\"v\\u001b\",\"b\":{\"$bytes\":\"AQIDBA==\"},\"a\":[null,true]}"
        );
        // the output is JSON
        let parsed: Json = serde_json::from_str(&render_value(&v)).unwrap();
        assert_eq!(parsed["b"]["$bytes"], "AQIDBA==");
        let nv = Reply::NonValue(NonValue {
            kind: "function".into(),
            type_name: Some("go\u{1b}".into()),
            text: None,
        });
        assert_eq!(
            render_reply(&nv, None),
            "{\"$nonValue\":{\"kind\":\"function\",\"type\":\"go\\u001b\"}}"
        );
        assert!(render_value(&Value::Float(f64::NAN)).contains("$nonValue"));
    }

    #[test]
    fn base64_pads_as_expected() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn errors_say_the_rule_and_the_text_is_a_json_string() {
        let e = ObjectsError::from_rpc(
            -32003,
            "refused: \u{1b}]0;title\u{7}".into(),
            Some(Value::Object(vec![(
                "reason".into(),
                Value::Text("not-allowed".into()),
            )])),
        );
        let line = render_error_line(&e);
        assert_eq!(
            line,
            "wsh objects: refused (not-allowed): \"refused: \\u001b]0;title\\u0007\""
        );
        assert!(line.chars().all(|c| !c.is_control()));
        assert_eq!(exit_code(&e), 3);
        let status = |kind| exit_code(&ObjectsError::from_rpc(0, String::new(), None).tap(kind));
        assert_eq!(status(ErrorKind::NotFound), 4);
        assert_eq!(status(ErrorKind::Unsupported), 5);
        assert_eq!(status(ErrorKind::Limit), 3);
        assert_eq!(status(ErrorKind::Closed), 1);
        assert_eq!(status(ErrorKind::Invalid), 2);
    }

    trait Tap {
        fn tap(self, kind: ErrorKind) -> Self;
    }
    impl Tap for ObjectsError {
        fn tap(mut self, kind: ErrorKind) -> Self {
            self.kind = kind;
            self
        }
    }

    #[test]
    fn a_path_starts_with_its_root() {
        let (root, path) = split_root("window.app.cart").unwrap();
        assert_eq!(
            (root.as_str(), path.segments()),
            ("window", &["app".to_string(), "cart".to_string()][..])
        );
        assert!(split_root("window").unwrap().1.is_empty());
        for bad in ["", ".a", "a..b", "a."] {
            assert!(split_root(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn arguments_are_json_and_a_bad_one_is_a_usage_error_before_dialling() {
        assert!(Plan::new(&Op::Call {
            path: "window.f".into(),
            args: vec!["{\"a\":1}".into(), "-3".into(), "\"x\"".into()],
        })
        .is_ok());
        assert!(Plan::new(&Op::Call {
            path: "window.f".into(),
            args: vec!["{nope".into()],
        })
        .is_err());
        assert!(Plan::new(&Op::Call {
            path: "window".into(),
            args: vec![],
        })
        .is_err());
        assert!(Plan::new(&Op::Set {
            path: "window.a".into(),
            value: "nope".into(),
        })
        .is_err());
        assert!(Plan::new(&Op::Watch {
            spec: "window.bus".into(),
            fields: vec![],
            count: None,
            capacity: 8,
        })
        .is_err());
        assert!(Plan::new(&Op::Watch {
            spec: "window.bus@ready".into(),
            fields: vec![],
            count: Some(1),
            capacity: 8,
        })
        .is_ok());
    }
}
