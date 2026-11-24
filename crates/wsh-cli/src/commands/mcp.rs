//! `wsh mcp [user@]host|URL` -- a stdio bridge so an MCP client that launches a command can reach an
//! MCP server behind a wsh host (wsh #127). The Rust twin of `wsh-mcp` (`bin/wsh-mcp.mjs`,
//! `src/mcp-stdio.mjs`), with the same behaviour:
//!
//! - stdin and stdout carry MCP messages, one JSON-RPC message per line; stdout carries nothing else,
//!   every diagnostic goes to stderr;
//! - it connects, logs in, opens the host's `mcp` rpc channel (`--channel NAME` for another) and passes
//!   the messages both ways verbatim, with the one translation the JS transport makes: an MCP
//!   `notifications/cancelled { requestId }` for a request in flight becomes the channel's
//!   `$/cancel { id }`, and a `$/cancel` from the host becomes a `notifications/cancelled`;
//! - if the connection drops after it was up it reconnects with a backoff (5 attempts from 500 ms,
//!   doubling), replays the client's `initialize` and `notifications/initialized` to the new channel
//!   without showing the client the answer, answers every request that was in flight with a
//!   JSON-RPC error (-32603, the client may retry) and holds what the client sends meanwhile (at most
//!   200 messages; a request past that is answered with an error);
//! - a host that offers no such channel is a clear error that lists the channels it does offer;
//! - exit status: 0 the client closed its side, 1 the host was lost for good, 2 it could not start.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use wsh_client::rpc::{RpcChannel, RpcOffer};
use wsh_client::WshClient;

use crate::commands::common::{connect_client_with, resolve_target, ResolvedTarget};

/// Longest message accepted from the client, as the JS bridge's `maxLineBytes`.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Messages held while reconnecting.
const MAX_QUEUED: usize = 200;

/// What the command was asked to do.
#[derive(Debug, Clone)]
pub struct Options {
    pub target: String,
    pub port: u16,
    pub transport: Option<String>,
    pub identity: String,
    pub channel: String,
    pub host_key: Option<String>,
    pub reconnect_attempts: u32,
    pub timeout: Duration,
}

/// Why the bridge could not (re)connect.
#[derive(Debug)]
enum Failure {
    /// Retrying will not help: a refused login or host key, or a host with no such channel.
    Fatal(String),
    Retry(String),
}

impl Failure {
    fn message(&self) -> &str {
        match self {
            Failure::Fatal(m) | Failure::Retry(m) => m,
        }
    }
}

/// `--host-key`: a hex fingerprint (what `known_hosts` records, `wsh keys` prints) or an
/// `ssh-ed25519 AAAA...` line; returns the lower-case hex SHA-256 of the raw Ed25519 key.
pub fn normalize_host_key(value: &str) -> Result<String, String> {
    let v = value.trim();
    let hex_like = v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
    if hex_like {
        return Ok(v.to_ascii_lowercase());
    }
    let mut parts = v.split_whitespace();
    if parts.next() == Some("ssh-ed25519") {
        if let Some(blob) = parts.next().and_then(decode_base64) {
            // string "ssh-ed25519", string key (32 bytes)
            let prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
            if blob.len() == prefix.len() + 32 && blob.starts_with(prefix) {
                return Ok(wsh_core::fingerprint(&blob[prefix.len()..]));
            }
        }
    }
    Err(format!(
        "--host-key: {value:?} is neither a 64-digit hex fingerprint nor an ssh-ed25519 key line"
    ))
}

fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A JSON-RPC id as a map key: JavaScript has one number type, so `1` and `1.0` are one id.
fn id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(s) => Some(format!("s:{s}")),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(format!("n:{i}"))
            } else if let Some(u) = n.as_u64() {
                Some(format!("n:{u}"))
            } else {
                let f = n.as_f64()?;
                if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
                    Some(format!("n:{}", f as i64))
                } else {
                    Some(format!("n:{f}"))
                }
            }
        }
        _ => None,
    }
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn note(line: &str) {
    eprintln!("wsh mcp: {line}");
}

/// stdout is the protocol: one line per message, flushed.
fn emit(message: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, message);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

enum Input {
    Line(String),
    TooLarge,
    Eof,
}

/// Reads the client's side: lines, in order, bounded.
async fn read_input(tx: mpsc::Sender<Input>) {
    let mut stdin = tokio::io::stdin();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut buf: Vec<u8> = Vec::new();
    let mut skipping = false;
    loop {
        let n = match stdin.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=nl).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if skipping {
                skipping = false;
                continue;
            }
            if line.len() > MAX_LINE_BYTES {
                if tx.send(Input::TooLarge).await.is_err() {
                    return;
                }
                continue;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            if !text.trim().is_empty() && tx.send(Input::Line(text)).await.is_err() {
                return;
            }
        }
        if buf.len() > MAX_LINE_BYTES {
            if tx.send(Input::TooLarge).await.is_err() {
                return;
            }
            buf.clear();
            skipping = true;
        }
    }
    if !skipping {
        let text = String::from_utf8_lossy(&buf).into_owned();
        if !text.trim().is_empty() {
            let _ = tx.send(Input::Line(text)).await;
        }
    }
    let _ = tx.send(Input::Eof).await;
}

struct Conn {
    client: WshClient,
    channel: Arc<RpcChannel>,
}

impl Conn {
    async fn shut(self) {
        self.channel.close().await;
        let _ = self.client.disconnect().await;
    }
}

/// Connect, log in, and open the channel; the checks JS `open()` makes.
async fn open(opts: &Options, resolved: &ResolvedTarget) -> Result<Conn, Failure> {
    let host_key = opts.host_key.clone();
    let secs = opts.timeout.as_secs().max(1);
    let client = connect_client_with(resolved, &opts.identity, move |c| {
        c.expect_host_key = host_key;
        c.timeout_secs = secs;
    })
    .await
    .map_err(|e| {
        let text = format!("cannot connect to {}: {e:#}", redact(&resolved.url));
        let lower = text.to_ascii_lowercase();
        if lower.contains("authentication failed")
            || lower.contains("not authorized")
            || lower.contains("host key")
            || lower.contains("authenticity of host")
        {
            Failure::Fatal(text)
        } else {
            Failure::Retry(text)
        }
    })?;
    let offer: RpcOffer = client.rpc_offer().await;
    if !offer.serves(&opts.channel) {
        let url = redact(&resolved.url);
        let _ = client.disconnect().await;
        let offered = if offer.enabled && !offer.protocols.is_empty() {
            format!(" (it offers: {})", offer.protocols.join(", "))
        } else {
            " (it offers no rpc channels)".to_string()
        };
        return Err(Failure::Fatal(format!(
            "the host at {url} offers no \"{}\" channel{offered}. Serve one with \
             createWshServer({{ rpc: {{ mcp: mcpServerAdapter(server) }} }}) or \
             createMemoryHost({{ rpc: {{ mcp }} }}); wsh-server serves no \"mcp\" channel.",
            opts.channel
        )));
    }
    let channel = match timeout(opts.timeout, client.open_rpc(&opts.channel)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            let _ = client.disconnect().await;
            return Err(Failure::Fatal(format!(
                "the host at {} did not open the \"{}\" channel: {e}",
                redact(&resolved.url),
                opts.channel
            )));
        }
        Err(_) => {
            let _ = client.disconnect().await;
            return Err(Failure::Retry(format!(
                "the host at {} did not open the \"{}\" channel in time",
                redact(&resolved.url),
                opts.channel
            )));
        }
    };
    Ok(Conn {
        client,
        channel: Arc::new(channel),
    })
}

fn redact(url: &str) -> String {
    crate::commands::common::redact_rendezvous(url)
}

/// The bridge's state: what is in flight, what is held, what to replay.
struct Bridge {
    conn: Option<Conn>,
    /// Requests forwarded to the host and not answered yet, by id key, with the id as the client sent it.
    inflight: HashMap<String, Value>,
    /// Requests the client cancelled: the host answers each with -32001, which the client must not see.
    cancelled: HashSet<String>,
    /// Requests the host made of the client and the client has not answered.
    host_requests: HashSet<String>,
    held: VecDeque<Value>,
    initialize: Option<Value>,
    initialized: Option<Value>,
    replay_seq: u64,
}

impl Bridge {
    fn new(conn: Conn) -> Self {
        Self {
            conn: Some(conn),
            inflight: HashMap::new(),
            cancelled: HashSet::new(),
            host_requests: HashSet::new(),
            held: VecDeque::new(),
            initialize: None,
            initialized: None,
            replay_seq: 0,
        }
    }

    /// One line from the client: parse it, remember what a reconnect must replay. `None`: it was
    /// not a message (an error was already sent).
    fn ingest(&mut self, line: &str) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => {
                emit(&error_response(&Value::Null, -32700, "Parse error"));
                return None;
            }
        };
        let valid = message.is_object() && message.get("jsonrpc") == Some(&json!("2.0"));
        if !valid {
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            emit(&error_response(
                &id,
                -32600,
                "Invalid Request: expected one JSON-RPC 2.0 message per line",
            ));
            return None;
        }
        match message.get("method").and_then(Value::as_str) {
            Some("initialize") if message.get("id").is_some() => {
                self.initialize = Some(message.clone())
            }
            Some("notifications/initialized") => self.initialized = Some(message.clone()),
            _ => {}
        }
        Some(message)
    }

    /// While there is no connection: hold the message, bounded.
    fn hold(&mut self, message: Value) {
        if self.held.len() >= MAX_QUEUED {
            if let (Some(id), Some(_)) = (message.get("id"), message.get("method")) {
                if !id.is_null() {
                    emit(&error_response(
                        id,
                        -32603,
                        "too many messages while reconnecting",
                    ));
                }
            }
            return;
        }
        self.held.push_back(message);
    }

    async fn from_client(&mut self, line: &str) {
        let Some(message) = self.ingest(line) else {
            return;
        };
        if self.conn.is_none() {
            self.hold(message);
        } else {
            self.forward(message).await;
        }
    }

    async fn forward(&mut self, message: Value) {
        let has_method = message.get("method").and_then(Value::as_str).is_some();
        let id = message.get("id").filter(|i| !i.is_null()).cloned();
        let mut outgoing = message.clone();
        let mut request_key = None;
        match (has_method, &id) {
            // A request.
            (true, Some(id)) => {
                if let Some(key) = id_key(id) {
                    self.inflight.insert(key.clone(), id.clone());
                    request_key = Some(key);
                }
            }
            // A notification: the MCP cancellation is `$/cancel` on this channel.
            (true, None) => {
                if message["method"] == "notifications/cancelled" {
                    if let Some(request_id) = message.pointer("/params/requestId") {
                        if let Some(key) = id_key(request_id) {
                            if self.inflight.remove(&key).is_some() {
                                self.cancelled.insert(key);
                                outgoing = json!({
                                    "jsonrpc": "2.0",
                                    "method": "$/cancel",
                                    "params": { "id": request_id },
                                });
                            }
                        }
                    }
                }
            }
            // The client's answer to a request the host made; one the host cancelled is dropped.
            (false, Some(id)) => {
                if !id_key(id).is_some_and(|k| self.host_requests.remove(&k)) {
                    return;
                }
            }
            (false, None) => return,
        }
        let Some(conn) = &self.conn else { return };
        if let Err(e) = conn.channel.send(&outgoing).await {
            match (&request_key, &id) {
                (Some(key), Some(id)) => {
                    self.inflight.remove(key);
                    emit(&error_response(id, -32603, &format!("wsh: {e}")));
                }
                _ => note(&format!("could not send a message: {e}")),
            }
        }
    }

    /// A message from the host, for the client.
    fn from_host(&mut self, message: Value) {
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").filter(|i| !i.is_null());
        match (method, id) {
            // A response.
            (None, Some(id)) => {
                if let Some(key) = id_key(id) {
                    // The answer to a request the client cancelled is the channel's own -32001.
                    if self.cancelled.remove(&key) {
                        return;
                    }
                    self.inflight.remove(&key);
                }
                emit(&message);
            }
            (None, None) => {} // an error about a message the host could not correlate
            (Some("$/cancel"), None) => {
                if let Some(request_id) = message.pointer("/params/id") {
                    if id_key(request_id).is_some_and(|k| self.host_requests.remove(&k)) {
                        emit(&json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": { "requestId": request_id, "reason": "cancelled" },
                        }));
                    }
                }
            }
            // The channel's own progress chunks (file reads); MCP progress is `notifications/progress`.
            (Some("$/progress"), None) => {}
            (Some(_), Some(id)) => {
                if let Some(key) = id_key(id) {
                    self.host_requests.insert(key);
                }
                emit(&message);
            }
            (Some(_), None) => emit(&message),
        }
    }

    /// The connection is gone: tell the client what it was waiting for.
    fn fail_inflight(&mut self) {
        for (_, id) in self.inflight.drain() {
            emit(&error_response(
                &id,
                -32603,
                "the connection to the wsh host was lost before this request was answered",
            ));
        }
        self.cancelled.clear();
        self.host_requests.clear();
    }
}

/// On a new channel the MCP server has not been initialized: do it again, as the client did, and keep
/// the answer to ourselves. Returns what the host said meanwhile (to pass on once connected).
async fn replay_initialization(
    conn: &Conn,
    initialize: &Value,
    initialized: Option<&Value>,
    seq: u64,
    wait: Duration,
) -> Result<Vec<Value>, Failure> {
    let id = format!("wsh-mcp-replay-{seq}");
    let mut request = initialize.clone();
    request["id"] = json!(id);
    conn.channel
        .send(&request)
        .await
        .map_err(|e| Failure::Retry(format!("could not replay initialize: {e}")))?;
    let mut meanwhile = Vec::new();
    let answer = timeout(wait, async {
        loop {
            match conn.channel.recv().await {
                Some(Ok(m)) if m.get("id") == Some(&json!(id)) && m.get("method").is_none() => {
                    return Some(m)
                }
                Some(Ok(m)) => meanwhile.push(m),
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten();
    match answer {
        Some(m) if m.get("error").is_none() => {}
        Some(m) => {
            return Err(Failure::Retry(format!(
                "the host did not accept the replayed initialize: {}",
                m.pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
            )))
        }
        None => {
            return Err(Failure::Retry(
                "the host did not accept the replayed initialize: no answer".into(),
            ))
        }
    }
    if let Some(n) = initialized {
        conn.channel
            .send(n)
            .await
            .map_err(|e| Failure::Retry(format!("could not replay initialized: {e}")))?;
    }
    Ok(meanwhile)
}

/// Run the bridge until the client closes its side (0) or the host is lost for good (1).
async fn run_bridge(opts: &Options, resolved: &ResolvedTarget, first: Conn) -> i32 {
    let (tx, mut rx) = mpsc::channel::<Input>(64);
    tokio::spawn(read_input(tx));
    let mut bridge = Bridge::new(first);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        if bridge.conn.is_none() {
            bridge.fail_inflight();
            match recover(&mut bridge, &mut rx, opts, resolved, &mut shutdown).await {
                Recovery::Back => continue,
                Recovery::Exit(code) => return code,
            }
        }
        let channel = bridge.conn.as_ref().expect("connected").channel.clone();
        tokio::select! {
            input = rx.recv() => match input {
                Some(Input::Line(line)) => bridge.from_client(&line).await,
                Some(Input::TooLarge) => emit(&error_response(
                    &Value::Null, -32600,
                    &format!("message too large (more than {MAX_LINE_BYTES} bytes)"),
                )),
                Some(Input::Eof) | None => {
                    finish(&mut bridge).await;
                    return 0;
                }
            },
            message = channel.recv() => match message {
                Some(Ok(m)) => bridge.from_host(m),
                Some(Err(e)) => {
                    note(&format!("channel error: {e}"));
                    lose(&mut bridge).await;
                }
                None => lose(&mut bridge).await,
            },
            _ = &mut shutdown => {
                finish(&mut bridge).await;
                return 0;
            }
        }
    }
}

async fn finish(bridge: &mut Bridge) {
    if let Some(conn) = bridge.conn.take() {
        conn.shut().await;
    }
}

async fn lose(bridge: &mut Bridge) {
    if let Some(conn) = bridge.conn.take() {
        tokio::spawn(conn.shut());
    }
}

enum Recovery {
    Back,
    Exit(i32),
}

/// What the loop was waiting on while reconnecting.
enum Waited<T> {
    Done(T),
    Closed,
}

/// Wait for `fut`, taking in what the client sends meanwhile (held, bounded). `Closed`: the client
/// ended its side, or a signal came.
async fn wait_holding<T>(
    bridge: &mut Bridge,
    rx: &mut mpsc::Receiver<Input>,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    fut: impl std::future::Future<Output = T>,
) -> Waited<T> {
    tokio::pin!(fut);
    loop {
        tokio::select! {
            out = &mut fut => return Waited::Done(out),
            input = rx.recv() => match input {
                Some(Input::Line(line)) => {
                    if let Some(message) = bridge.ingest(&line) {
                        bridge.hold(message);
                    }
                }
                Some(Input::TooLarge) => emit(&error_response(
                    &Value::Null, -32600,
                    &format!("message too large (more than {MAX_LINE_BYTES} bytes)"),
                )),
                Some(Input::Eof) | None => return Waited::Closed,
            },
            _ = shutdown.as_mut() => return Waited::Closed,
        }
    }
}

async fn recover(
    bridge: &mut Bridge,
    rx: &mut mpsc::Receiver<Input>,
    opts: &Options,
    resolved: &ResolvedTarget,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Recovery {
    let attempts = opts.reconnect_attempts;
    let mut delay = Duration::from_millis(500);
    for attempt in 1..=attempts {
        note(&format!(
            "connection lost; reconnecting (attempt {attempt} of {attempts})"
        ));
        if let Waited::Closed = wait_holding(bridge, rx, shutdown, sleep(delay)).await {
            return Recovery::Exit(0);
        }
        delay = (delay * 2).min(Duration::from_secs(10));
        let initialize = bridge.initialize.clone();
        let initialized = bridge.initialized.clone();
        bridge.replay_seq += 1;
        let seq = bridge.replay_seq;
        let wait = opts.timeout;
        let attempt_result = wait_holding(bridge, rx, shutdown, async {
            let conn = open(opts, resolved).await?;
            let meanwhile = match &initialize {
                Some(init) => {
                    match replay_initialization(&conn, init, initialized.as_ref(), seq, wait).await
                    {
                        Ok(m) => m,
                        Err(e) => {
                            conn.shut().await;
                            return Err(e);
                        }
                    }
                }
                None => Vec::new(),
            };
            Ok::<_, Failure>((conn, meanwhile))
        })
        .await;
        match attempt_result {
            Waited::Closed => return Recovery::Exit(0),
            Waited::Done(Ok((conn, meanwhile))) => {
                bridge.conn = Some(conn);
                note("reconnected");
                for m in meanwhile {
                    bridge.from_host(m);
                }
                while let Some(message) = bridge.held.pop_front() {
                    bridge.forward(message).await;
                }
                return Recovery::Back;
            }
            Waited::Done(Err(failure)) => {
                note(&format!("reconnect failed: {}", failure.message()));
                if matches!(failure, Failure::Fatal(_)) {
                    break;
                }
            }
        }
    }
    note(if attempts > 0 {
        "could not reconnect; giving up"
    } else {
        "connection lost"
    });
    for message in bridge.held.drain(..) {
        if let (Some(id), Some(_)) = (message.get("id"), message.get("method")) {
            if !id.is_null() {
                emit(&error_response(id, -32603, "the wsh host is unreachable"));
            }
        }
    }
    Recovery::Exit(1)
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

/// `wsh mcp`: never returns; the process exits with the bridge's status.
pub async fn run(opts: Options) -> anyhow::Result<()> {
    let code = start(opts).await;
    std::process::exit(code);
}

async fn start(opts: Options) -> i32 {
    if !wsh_client::rpc::valid_protocol_name(&opts.channel) {
        eprintln!("wsh mcp: {:?} is not a valid channel name", opts.channel);
        return 2;
    }
    let resolved = match resolve_target(&opts.target, opts.port, opts.transport.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wsh mcp: {e:#}");
            return 2;
        }
    };
    let first = match open(&opts, &resolved).await {
        Ok(c) => c,
        Err(f) => {
            eprintln!("wsh mcp: {}", f.message());
            return 2;
        }
    };
    run_bridge(&opts, &resolved, first).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_one_number_type() {
        assert_eq!(id_key(&json!(1)), id_key(&json!(1.0)));
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
        assert_eq!(id_key(&json!(null)), None);
        assert_eq!(id_key(&json!({})), None);
    }

    #[test]
    fn a_host_key_is_a_fingerprint_or_an_ssh_line() {
        let fp = "266d39f1ffe60713ab836382fa8373407c8facaa88a3ddaf80c1cd5433e80dcc";
        assert_eq!(normalize_host_key(fp).unwrap(), fp);
        assert_eq!(normalize_host_key(&fp.to_uppercase()).unwrap(), fp);
        assert!(normalize_host_key("nonsense").is_err());
        assert!(normalize_host_key("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn an_ssh_ed25519_line_gives_the_fingerprint_of_its_key() {
        let mut blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20".to_vec();
        blob.extend([7u8; 32]);
        // base64 by hand: no encoder dependency for a test
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for c in blob.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    b64.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    b64.push('=');
                }
            }
        }
        let line = format!("ssh-ed25519 {b64} someone@host");
        assert_eq!(
            normalize_host_key(&line).unwrap(),
            wsh_core::fingerprint(&[7u8; 32])
        );
    }
}
