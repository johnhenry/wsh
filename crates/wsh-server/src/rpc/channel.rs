//! One server-side end of an `rpc` channel: JSON-RPC 2.0 over a CBOR sequence.
//!
//! Transport-free: the engine is fed [`Input`]s and writes encoded messages to
//! an `mpsc::Sender<Vec<u8>>`; `session.rs` binds both to a QMux stream. This
//! is the request-serving half of `RpcChannel` in `src/rpc.mjs` (a wsh host
//! never issues requests on `wsh-host` / `wsh-fs`), including the reserved
//! `$/cancel` and `$/progress` notifications and the same error codes.

use super::protocols::Protocol;
use super::seq::CborSequenceDecoder;
use super::{code, get, id_display, id_key, map, text, IdKey, RpcError};
use ciborium::value::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// What the transport tells the engine.
#[derive(Debug)]
pub enum Input {
    /// Bytes received on the stream.
    Data(Vec<u8>),
    /// The peer finished its side of the stream (FIN).
    End,
    /// The stream was reset.
    Reset,
    /// The peer closed the channel (a `Close` control message).
    Kill,
}

/// Why [`run`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// The host ended it (protocol error): close the stream, then tell the client the channel is over.
    HostClosed(String),
    /// The client half-closed: same follow-up as `HostClosed`.
    StreamEnd,
    /// The client sent `Close`: close our end of the stream, say nothing.
    PeerKilled,
    /// The stream was reset: nothing to close.
    StreamReset,
    /// The connection is going away.
    Dropped,
}

#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    pub max_message_bytes: usize,
    pub max_inflight: usize,
}

/// What a handler sees of its request.
pub struct RpcContext {
    id: Value,
    cancel: watch::Receiver<bool>,
    out: mpsc::Sender<Vec<u8>>,
    done: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    max_message_bytes: usize,
}

impl RpcContext {
    /// The channel's message limit (a handler sizes its chunks from it).
    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// True once the caller sent `$/cancel` or the channel closed.
    pub fn aborted(&self) -> bool {
        *self.cancel.borrow() || self.closed.load(Ordering::Relaxed)
    }

    /// Resolves when the request is cancelled or the channel closes.
    #[cfg(test)]
    pub async fn cancelled(&self) {
        let mut rx = self.cancel.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Send a `$/progress` for this request. Errors if the chunk does not fit the message limit.
    pub async fn progress(&self, chunk: Value) -> Result<(), RpcError> {
        if self.done.load(Ordering::Relaxed) || self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let msg = map([
            ("jsonrpc", text("2.0")),
            ("method", text("$/progress")),
            ("params", map([("id", self.id.clone()), ("chunk", chunk)])),
        ]);
        let bytes = encode(&msg, self.max_message_bytes)?;
        // A closed sink means the channel is going away; the handler's answer is moot.
        let _ = self.out.send(bytes).await;
        Ok(())
    }
}

/// Encode a message, refusing one over the limit.
pub fn encode(msg: &Value, max: usize) -> Result<Vec<u8>, RpcError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(msg, &mut bytes)
        .map_err(|e| RpcError::new(code::INTERNAL, format!("encode failed: {e}")))?;
    if bytes.len() > max {
        return Err(RpcError::too_large("message", bytes.len(), max));
    }
    Ok(bytes)
}

fn response(id: &Value, result: Result<Value, RpcError>) -> Value {
    match result {
        Ok(v) => map([("jsonrpc", text("2.0")), ("id", id.clone()), ("result", v)]),
        Err(e) => map([
            ("jsonrpc", text("2.0")),
            ("id", id.clone()),
            ("error", e.to_value()),
        ]),
    }
}

fn error_response(id: Value, e: RpcError) -> Value {
    response(&id, Err(e))
}

struct Inflight {
    cancel: watch::Sender<bool>,
    done: Arc<AtomicBool>,
}

struct Engine {
    cfg: ChannelConfig,
    protocol: Arc<Protocol>,
    out: mpsc::Sender<Vec<u8>>,
    inflight: HashMap<IdKey, Inflight>,
    done_tx: mpsc::UnboundedSender<(IdKey, Value, Result<Value, RpcError>)>,
    closed: Arc<AtomicBool>,
}

impl Engine {
    /// Best-effort send of a small control message (never over-limit-checked, never fails).
    async fn send_raw(&self, msg: Value) {
        let mut bytes = Vec::new();
        if ciborium::into_writer(&msg, &mut bytes).is_ok() {
            let _ = self.out.send(bytes).await;
        }
    }

    async fn dispatch(&mut self, m: Value) {
        let is_map = matches!(m, Value::Map(_));
        if !is_map || !matches!(get(&m, "jsonrpc"), Some(Value::Text(v)) if v == "2.0") {
            return self.invalid(&m).await;
        }
        match get(&m, "method") {
            Some(Value::Text(method)) => {
                match get(&m, "params") {
                    None
                    | Some(
                        Value::Null
                        | Value::Map(_)
                        | Value::Array(_)
                        | Value::Bytes(_)
                        | Value::Tag(..),
                    ) => {}
                    Some(_) => return self.invalid(&m).await,
                }
                match get(&m, "id") {
                    None => self.notification(method, get(&m, "params")).await,
                    Some(id) => {
                        let Some(key) = id_key(id) else {
                            return self
                                .send_raw(error_response(
                                    Value::Null,
                                    RpcError::new(code::INVALID_REQUEST, "invalid request id"),
                                ))
                                .await;
                        };
                        self.request(key, id.clone(), method.clone(), get(&m, "params").cloned())
                            .await
                    }
                }
            }
            Some(_) => self.invalid(&m).await,
            // A response: this end issues no requests, so there is nothing to correlate it with.
            None => {}
        }
    }

    async fn invalid(&self, m: &Value) {
        let id = get(m, "id")
            .filter(|id| id_key(id).is_some())
            .cloned()
            .unwrap_or(Value::Null);
        self.send_raw(error_response(
            id,
            RpcError::new(code::INVALID_REQUEST, "invalid JSON-RPC 2.0 message"),
        ))
        .await;
    }

    async fn notification(&mut self, method: &str, params: Option<&Value>) {
        if method != "$/cancel" {
            // `$/progress` and anything else: no handlers registered on this end.
            return;
        }
        let Some(id) = params.and_then(|p| get(p, "id")) else {
            return;
        };
        let Some(key) = id_key(id) else { return };
        let Some(rec) = self.inflight.get(&key) else {
            return;
        };
        if rec.done.swap(true, Ordering::Relaxed) {
            return;
        }
        let _ = rec.cancel.send(true);
        self.inflight.remove(&key);
        self.send_raw(error_response(
            id.clone(),
            RpcError::with_reason(code::CANCELLED, "request cancelled", "cancelled"),
        ))
        .await;
    }

    async fn request(&mut self, key: IdKey, id: Value, method: String, params: Option<Value>) {
        if self.inflight.contains_key(&key) {
            let msg = format!("request id {} is already in flight", id_display(&id));
            return self
                .send_raw(error_response(
                    id,
                    RpcError::new(code::INVALID_REQUEST, msg),
                ))
                .await;
        }
        if self.inflight.len() >= self.cfg.max_inflight {
            let msg = format!("more than {} requests in flight", self.cfg.max_inflight);
            return self
                .send_raw(error_response(
                    id,
                    RpcError::with_reason(code::STREAM_LIMIT, msg, "stream-limit"),
                ))
                .await;
        }
        if !self.protocol.handles(&method) {
            return self
                .send_raw(error_response(
                    id,
                    RpcError::new(
                        code::METHOD_NOT_FOUND,
                        format!("method not found: {method}"),
                    ),
                ))
                .await;
        }
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let done = Arc::new(AtomicBool::new(false));
        self.inflight.insert(
            key.clone(),
            Inflight {
                cancel: cancel_tx,
                done: done.clone(),
            },
        );
        let ctx = RpcContext {
            id: id.clone(),
            cancel: cancel_rx,
            out: self.out.clone(),
            done,
            closed: self.closed.clone(),
            max_message_bytes: self.cfg.max_message_bytes,
        };
        let protocol = self.protocol.clone();
        let done_tx = self.done_tx.clone();
        tokio::spawn(async move {
            let result = protocol
                .call(&method, params.unwrap_or(Value::Null), &ctx)
                .await;
            let _ = done_tx.send((key, id, result));
        });
    }

    async fn complete(&mut self, key: IdKey, id: Value, result: Result<Value, RpcError>) {
        // Cancelled or closed while working: the answer was already sent (or is moot).
        let Some(rec) = self.inflight.remove(&key) else {
            return;
        };
        if rec.done.swap(true, Ordering::Relaxed) {
            return;
        }
        match encode(&response(&id, result), self.cfg.max_message_bytes) {
            Ok(bytes) => {
                let _ = self.out.send(bytes).await;
            }
            Err(e) => {
                let data = e.data.clone();
                self.send_raw(error_response(
                    id,
                    RpcError {
                        code: code::INTERNAL,
                        message: e.message,
                        data,
                    },
                ))
                .await;
            }
        }
    }

    fn teardown(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        for (_, rec) in self.inflight.drain() {
            rec.done.store(true, Ordering::Relaxed);
            let _ = rec.cancel.send(true);
        }
    }
}

/// Serve one channel until it ends. Everything the peer should see is written to `out`.
pub async fn run(
    cfg: ChannelConfig,
    protocol: Arc<Protocol>,
    mut input: mpsc::UnboundedReceiver<Input>,
    out: mpsc::Sender<Vec<u8>>,
) -> Ended {
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let mut engine = Engine {
        cfg,
        protocol,
        out,
        inflight: HashMap::new(),
        done_tx,
        closed: Arc::new(AtomicBool::new(false)),
    };
    let mut decoder = CborSequenceDecoder::new(cfg.max_message_bytes);
    let ended = loop {
        tokio::select! {
            msg = input.recv() => match msg {
                None => break Ended::Dropped,
                Some(Input::Kill) => break Ended::PeerKilled,
                Some(Input::Reset) => break Ended::StreamReset,
                Some(Input::End) => break Ended::StreamEnd,
                Some(Input::Data(bytes)) => match decoder.feed(&bytes) {
                    Ok(items) => {
                        for item in items {
                            engine.dispatch(item).await;
                        }
                    }
                    Err(e) => {
                        engine.send_raw(error_response(Value::Null, e.clone())).await;
                        let reason = if e.code == code::PARSE {
                            "parse-error".to_string()
                        } else {
                            match &e.data {
                                Some(d) => match get(d, "reason") {
                                    Some(Value::Text(r)) => r.clone(),
                                    _ => "protocol-error".to_string(),
                                },
                                None => "protocol-error".to_string(),
                            }
                        };
                        break Ended::HostClosed(reason);
                    }
                },
            },
            Some((key, id, result)) = done_rx.recv() => engine.complete(key, id, result).await,
        }
    };
    engine.teardown();
    ended
}

#[cfg(test)]
mod tests {
    use super::super::fs::FileAccess;
    use super::super::protocols::HostInfo;
    use super::super::{int, uint};
    use super::*;
    use std::time::Duration;

    fn enc(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    fn req(id: i64, method: &str, params: Value) -> Vec<u8> {
        enc(&map([
            ("jsonrpc", text("2.0")),
            ("id", int(id)),
            ("method", text(method)),
            ("params", params),
        ]))
    }

    fn notif(method: &str, params: Value) -> Vec<u8> {
        enc(&map([
            ("jsonrpc", text("2.0")),
            ("method", text(method)),
            ("params", params),
        ]))
    }

    struct Harness {
        input: mpsc::UnboundedSender<Input>,
        out: mpsc::Receiver<Vec<u8>>,
        task: tokio::task::JoinHandle<Ended>,
        dec: CborSequenceDecoder,
        queued: std::collections::VecDeque<Value>,
    }

    fn start(protocol: Protocol, cfg: ChannelConfig) -> Harness {
        let (itx, irx) = mpsc::unbounded_channel();
        let (otx, orx) = mpsc::channel(256);
        let task = tokio::spawn(run(cfg, Arc::new(protocol), irx, otx));
        Harness {
            input: itx,
            out: orx,
            task,
            dec: CborSequenceDecoder::new(10 * 1024 * 1024),
            queued: Default::default(),
        }
    }

    fn cfg() -> ChannelConfig {
        ChannelConfig {
            max_message_bytes: 4096,
            max_inflight: 64,
        }
    }

    impl Harness {
        fn send(&self, bytes: Vec<u8>) {
            self.input.send(Input::Data(bytes)).unwrap();
        }
        async fn next(&mut self) -> Value {
            loop {
                if let Some(v) = self.queued.pop_front() {
                    return v;
                }
                let bytes = tokio::time::timeout(Duration::from_secs(5), self.out.recv())
                    .await
                    .expect("timed out waiting for output")
                    .expect("engine closed its output");
                self.queued.extend(self.dec.feed(&bytes).unwrap());
            }
        }
        async fn quiet(&mut self) -> bool {
            tokio::time::timeout(Duration::from_millis(150), self.out.recv())
                .await
                .is_err()
        }
    }

    fn err_code(v: &Value) -> i64 {
        match get(get(v, "error").expect("error member"), "code") {
            Some(Value::Integer(i)) => i128::from(*i) as i64,
            other => panic!("no code: {other:?}"),
        }
    }

    fn host() -> Protocol {
        Protocol::Host(Arc::new(HostInfo {
            version: "9.9.9".into(),
            features: vec!["rpc".into()],
            user: "alice".into(),
            protocols: vec!["wsh-host".into()],
            max_message_bytes: 4096,
        }))
    }

    #[tokio::test]
    async fn answers_a_request_by_id() {
        let mut h = start(host(), cfg());
        h.send(req(7, "host.info", Value::Map(vec![])));
        let r = h.next().await;
        assert_eq!(get(&r, "id"), Some(&int(7)));
        let result = get(&r, "result").unwrap();
        assert_eq!(get(result, "user"), Some(&text("alice")));
        assert_eq!(get(result, "version"), Some(&text("9.9.9")));
    }

    #[tokio::test]
    async fn unknown_method_is_32601() {
        let mut h = start(host(), cfg());
        h.send(req(1, "host.nope", Value::Null));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::METHOD_NOT_FOUND);
        assert_eq!(
            get(get(&r, "error").unwrap(), "message"),
            Some(&text("method not found: host.nope"))
        );
    }

    #[tokio::test]
    async fn invalid_messages_are_32600_and_keep_the_channel_open() {
        let mut h = start(host(), cfg());
        h.send(enc(&map([("jsonrpc", text("1.0")), ("id", int(3))])));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(get(&r, "id"), Some(&int(3)));
        h.send(enc(&Value::Text("hello".into())));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(get(&r, "id"), Some(&Value::Null));
        // an id that is not a string or number
        h.send(enc(&map([
            ("jsonrpc", text("2.0")),
            ("id", Value::Bool(true)),
            ("method", text("host.ping")),
        ])));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(
            get(get(&r, "error").unwrap(), "message"),
            Some(&text("invalid request id"))
        );
        h.send(req(4, "host.ping", Value::Null));
        assert!(get(&h.next().await, "result").is_some());
    }

    #[tokio::test]
    async fn string_ids_and_notifications() {
        let mut h = start(host(), cfg());
        h.send(enc(&map([
            ("jsonrpc", text("2.0")),
            ("method", text("host.ping")),
        ])));
        assert!(h.quiet().await, "a notification gets no response");
        h.send(enc(&map([
            ("jsonrpc", text("2.0")),
            ("id", text("abc")),
            ("method", text("host.ping")),
        ])));
        assert_eq!(get(&h.next().await, "id"), Some(&text("abc")));
    }

    #[tokio::test]
    async fn parse_error_answers_then_closes() {
        let mut h = start(host(), cfg());
        h.send(vec![0x1c]);
        let r = h.next().await;
        assert_eq!(err_code(&r), code::PARSE);
        assert_eq!(get(&r, "id"), Some(&Value::Null));
        assert_eq!(
            h.task.await.unwrap(),
            Ended::HostClosed("parse-error".into())
        );
    }

    #[tokio::test]
    async fn oversized_message_answers_then_closes_with_its_reason() {
        let mut h = start(host(), cfg());
        // a 5000-byte byte string against a 4096 limit
        let mut bytes = vec![0x59, 0x13, 0x88];
        bytes.extend(vec![0u8; 5000]);
        h.send(bytes);
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(
            h.task.await.unwrap(),
            Ended::HostClosed("message-too-large".into())
        );
    }

    #[tokio::test]
    async fn duplicate_inflight_id_is_refused_and_the_first_still_answers() {
        let mut h = start(Protocol::Test, cfg());
        h.send(req(1, "slow", Value::Null));
        h.send(req(1, "slow", Value::Null));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(
            get(get(&r, "error").unwrap(), "message"),
            Some(&text("request id 1 is already in flight"))
        );
        h.send(notif("$/cancel", map([("id", int(1))])));
        assert_eq!(err_code(&h.next().await), code::CANCELLED);
    }

    #[tokio::test]
    async fn stream_limit_is_32002() {
        let mut h = start(
            Protocol::Test,
            ChannelConfig {
                max_message_bytes: 4096,
                max_inflight: 2,
            },
        );
        h.send(req(1, "slow", Value::Null));
        h.send(req(2, "slow", Value::Null));
        h.send(req(3, "slow", Value::Null));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::STREAM_LIMIT);
        assert_eq!(get(&r, "id"), Some(&int(3)));
        assert_eq!(
            get(get(&r, "error").unwrap(), "message"),
            Some(&text("more than 2 requests in flight"))
        );
    }

    #[tokio::test]
    async fn cancel_answers_32001_immediately_and_drops_the_late_result() {
        let mut h = start(Protocol::Test, cfg());
        h.send(req(5, "slow", Value::Null));
        assert!(h.quiet().await);
        h.send(notif("$/cancel", map([("id", int(5))])));
        let r = h.next().await;
        assert_eq!(get(&r, "id"), Some(&int(5)));
        assert_eq!(err_code(&r), code::CANCELLED);
        // the handler observed the cancellation and returned; its result must not surface
        assert!(h.quiet().await, "the late result was dropped");
        // cancelling something unknown is a no-op, and the id can be reused
        h.send(notif("$/cancel", map([("id", int(99))])));
        h.send(req(5, "echo", map([("a", int(1))])));
        let r = h.next().await;
        assert_eq!(get(&r, "id"), Some(&int(5)));
        assert!(get(&r, "result").is_some());
    }

    #[tokio::test]
    async fn progress_precedes_the_result_and_oversized_progress_fails_the_request() {
        let mut h = start(Protocol::Test, cfg());
        h.send(req(1, "burst", map([("n", int(3)), ("bytes", int(100))])));
        for _ in 0..3 {
            let p = h.next().await;
            assert_eq!(get(&p, "method"), Some(&text("$/progress")));
            let params = get(&p, "params").unwrap();
            assert_eq!(get(params, "id"), Some(&int(1)));
            assert!(matches!(get(params, "chunk"), Some(Value::Bytes(b)) if b.len() == 100));
        }
        let r = h.next().await;
        assert_eq!(get(get(&r, "result").unwrap(), "sent"), Some(&uint(3)));
        // a chunk over the limit is the handler's error
        h.send(req(2, "burst", map([("n", int(1)), ("bytes", int(5000))])));
        let r = h.next().await;
        assert_eq!(err_code(&r), code::INVALID_REQUEST);
        assert_eq!(
            get(get(get(&r, "error").unwrap(), "data").unwrap(), "reason"),
            Some(&text("message-too-large"))
        );
    }

    #[tokio::test]
    async fn an_oversized_result_becomes_an_internal_error_not_silence() {
        let mut h = start(Protocol::Test, cfg());
        // a small request whose result cannot fit the 4096 byte limit
        h.send(req(1, "big", map([("bytes", int(5000))])));
        let r = h.next().await;
        assert_eq!(get(&r, "id"), Some(&int(1)));
        assert_eq!(err_code(&r), code::INTERNAL);
        assert_eq!(
            get(get(get(&r, "error").unwrap(), "data").unwrap(), "reason"),
            Some(&text("message-too-large"))
        );
        // the channel is still usable
        h.send(req(2, "echo", map([("a", int(1))])));
        assert!(get(&h.next().await, "result").is_some());
    }

    #[tokio::test]
    async fn end_kill_reset_and_drop_end_the_channel() {
        for (input, want) in [
            (Input::End, Ended::StreamEnd),
            (Input::Kill, Ended::PeerKilled),
            (Input::Reset, Ended::StreamReset),
        ] {
            let h = start(host(), cfg());
            h.input.send(input).unwrap();
            assert_eq!(h.task.await.unwrap(), want);
        }
        let h = start(host(), cfg());
        drop(h.input);
        assert_eq!(h.task.await.unwrap(), Ended::Dropped);
    }

    #[tokio::test]
    async fn closing_aborts_inflight_handlers() {
        let (itx, irx) = mpsc::unbounded_channel();
        let (otx, mut orx) = mpsc::channel(8);
        let task = tokio::spawn(run(cfg(), Arc::new(Protocol::Test), irx, otx));
        itx.send(Input::Data(req(1, "slow", Value::Null))).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        itx.send(Input::Kill).unwrap();
        assert_eq!(task.await.unwrap(), Ended::PeerKilled);
        // the handler was told to stop: once it has, every sender is gone and the sink closes
        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            while orx.recv().await.is_some() {}
        })
        .await;
        assert!(drained.is_ok(), "the in-flight handler never stopped");
    }

    #[tokio::test]
    async fn fs_read_streams_chunks_then_summarises() {
        let dir = tempdir("engine-read");
        std::fs::write(dir.join("big.bin"), vec![0xab; 1000]).unwrap();
        let files = FileAccess::new(&dir, false, 1 << 20).unwrap();
        let mut h = start(
            Protocol::Fs(files),
            ChannelConfig {
                max_message_bytes: 576, // chunk = max(64, 576 - 512) = 64
                max_inflight: 8,
            },
        );
        h.send(req(1, "read", map([("path", text("/big.bin"))])));
        let mut got = 0usize;
        loop {
            let m = h.next().await;
            if get(&m, "method").is_some() {
                match get(get(&m, "params").unwrap(), "chunk") {
                    Some(Value::Bytes(b)) => {
                        assert!(b.len() <= 64);
                        got += b.len();
                    }
                    other => panic!("chunk: {other:?}"),
                }
            } else {
                let r = get(&m, "result").unwrap();
                assert_eq!(get(r, "size"), Some(&uint(1000)));
                assert_eq!(get(r, "length"), Some(&uint(1000)));
                assert_eq!(get(r, "eof"), Some(&Value::Bool(true)));
                break;
            }
        }
        assert_eq!(got, 1000);
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "wsh-rpc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
