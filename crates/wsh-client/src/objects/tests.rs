//! The objects client against a scripted host: what it sends, how it reads the answers, and the rules it enforces
//! before anything is sent.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wsh_core::rpc_codec::{encode_cbor, Cbor, CborSequenceDecoder};

use super::*;
use crate::rpc::{test_channel, VirtualInbound};
use crate::session::ControlAction;

fn t(s: &str) -> Cbor {
    Cbor::Text(s.to_string())
}

fn int(i: i64) -> Cbor {
    Cbor::Integer(i.into())
}

fn cmap(entries: &[(&str, Cbor)]) -> Cbor {
    Cbor::Map(entries.iter().map(|(k, v)| (t(k), v.clone())).collect())
}

fn texts(items: &[&str]) -> Cbor {
    Cbor::Array(items.iter().map(|s| t(s)).collect())
}

struct Req {
    id: u64,
    method: String,
    params: Cbor,
}

/// The host's side: reads what the client wrote, answers by writing to the channel's inbound.
struct Host {
    inbound: Arc<VirtualInbound>,
    actions: mpsc::Receiver<ControlAction>,
    decoder: CborSequenceDecoder,
    queued: VecDeque<Cbor>,
    closed: bool,
}

impl Host {
    async fn next(&mut self) -> Cbor {
        loop {
            if let Some(m) = self.queued.pop_front() {
                return m;
            }
            match tokio::time::timeout(Duration::from_secs(5), self.actions.recv())
                .await
                .expect("the client wrote nothing")
                .expect("actions ended")
            {
                ControlAction::Data { data, .. } => {
                    self.queued.extend(self.decoder.feed_values(&data).unwrap());
                }
                ControlAction::Close { .. } => self.closed = true,
                _ => {}
            }
        }
    }

    async fn request(&mut self) -> Req {
        let m = self.next().await;
        Req {
            id: cbor_u64(&m, "id").expect("a request has an id"),
            method: cbor_text(&m, "method").unwrap().to_string(),
            params: cbor_get(&m, "params").cloned().unwrap_or(Cbor::Null),
        }
    }

    fn write(&self, message: Cbor) {
        self.inbound.on_data(&encode_cbor(&message).unwrap());
    }

    fn reply(&self, id: u64, result: Cbor) {
        self.write(cmap(&[
            ("jsonrpc", t("2.0")),
            ("id", int(id as i64)),
            ("result", result),
        ]));
    }

    fn refuse(&self, id: u64, code: i64, reason: &str, message: &str) {
        self.write(cmap(&[
            ("jsonrpc", t("2.0")),
            ("id", int(id as i64)),
            (
                "error",
                cmap(&[
                    ("code", int(code)),
                    ("message", t(message)),
                    ("data", cmap(&[("reason", t(reason))])),
                ]),
            ),
        ]));
    }

    fn notify(&self, method: &str, params: Cbor) {
        self.write(cmap(&[
            ("jsonrpc", t("2.0")),
            ("method", t(method)),
            ("params", params),
        ]));
    }

    fn event(&self, id: u64, seq: i64, dropped: Option<i64>, data: Cbor) {
        let mut p = vec![("id", int(id as i64)), ("seq", int(seq)), ("data", data)];
        if let Some(d) = dropped {
            p.push(("dropped", int(d)));
        }
        self.notify("event", cmap(&p));
    }

    /// Nothing more is written by the client (it has not been waited for: look at what is already queued).
    async fn quiet(&mut self) -> bool {
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Ok(a) = self.actions.try_recv() {
            if let ControlAction::Data { data, .. } = a {
                self.queued.extend(self.decoder.feed_values(&data).unwrap());
            }
        }
        self.queued.is_empty()
    }
}

async fn open(roots: &[&str], features: Option<&[&str]>) -> (ObjectsClient, Host) {
    let tc = test_channel(1024 * 1024, true);
    let mut host = Host {
        inbound: tc.inbound,
        actions: tc.actions,
        decoder: CborSequenceDecoder::new(1024 * 1024),
        queued: VecDeque::new(),
        closed: false,
    };
    let opening = tokio::spawn(ObjectsClient::from_channel(
        tc.channel,
        OpenOptions::default(),
    ));
    let req = host.request().await;
    assert_eq!(req.method, "roots");
    let mut answer = vec![("roots", texts(roots))];
    if let Some(f) = features {
        answer.push(("features", texts(f)));
    }
    host.reply(req.id, cmap(&answer));
    (opening.await.unwrap().unwrap(), host)
}

// ── values ──

#[test]
fn values_round_trip_through_cbor_with_bytes_native() {
    let v = Value::Object(vec![
        ("n".into(), Value::Int(-7)),
        ("f".into(), Value::Float(1.5)),
        ("b".into(), Value::Bytes(vec![0, 255])),
        (
            "a".into(),
            Value::Array(vec![
                Value::Null,
                Value::Bool(true),
                Value::Text("x".into()),
            ]),
        ),
    ]);
    let back = Value::from_cbor(v.to_cbor()).unwrap();
    assert_eq!(back, v);
    assert_eq!(v.member("b"), Some(&Value::Bytes(vec![0, 255])));
}

#[test]
fn a_map_key_that_is_not_text_and_a_huge_integer_are_the_hosts_breach() {
    let bad_key = Cbor::Map(vec![(int(1), t("x"))]);
    assert_eq!(
        Value::from_cbor(bad_key).unwrap_err().kind,
        ErrorKind::Protocol
    );
    let huge = Cbor::Integer(u64::MAX.into());
    assert_eq!(
        Value::from_cbor(huge).unwrap_err().kind,
        ErrorKind::Protocol
    );
}

#[test]
fn a_value_serialises_as_json_would_but_keeps_bytes_distinct() {
    let v = Value::Array(vec![Value::Int(1), Value::Text("a\u{7}".into())]);
    assert_eq!(serde_json::to_string(&v).unwrap(), "[1,\"a\\u0007\"]");
    let from_json: Value = serde_json::from_str(r#"{"a":[1,2.5,null,"s"],"b":true}"#).unwrap();
    assert_eq!(
        from_json,
        Value::Object(vec![
            (
                "a".into(),
                Value::Array(vec![
                    Value::Int(1),
                    Value::Float(2.5),
                    Value::Null,
                    Value::Text("s".into())
                ])
            ),
            ("b".into(), Value::Bool(true)),
        ])
    );
    // bytes are not JSON's array of numbers when the serializer has bytes
    let mut cbor = Vec::new();
    ciborium_roundtrip(&Value::Bytes(vec![1, 2]), &mut cbor);
    assert_eq!(cbor, vec![0x42, 1, 2]);
}

fn ciborium_roundtrip(v: &Value, out: &mut Vec<u8>) {
    out.extend(encode_cbor(&v.to_cbor()).unwrap());
}

#[test]
fn a_u64_above_i64_is_a_float_as_javascript_would_have_it() {
    let v: Value = serde_json::from_str("18446744073709551615").unwrap();
    assert!(matches!(v, Value::Float(_)));
}

// ── paths ──

#[test]
fn paths_split_on_dots_and_segments_are_checked_before_anything_is_sent() {
    assert_eq!(Path::parse("a.b.c").segments(), ["a", "b", "c"]);
    assert!(Path::parse("").is_empty());
    assert_eq!(Path::from(["x", "y"]).segments(), ["x", "y"]);
    assert!(check_segment("fine").is_ok());
    for bad in ["", "a.b", &"x".repeat(257)] {
        assert_eq!(check_segment(bad).unwrap_err().kind, ErrorKind::Invalid);
    }
    assert!(Path::parse("a..b").check().is_err());
}

// ── errors ──

#[test]
fn the_hosts_codes_and_reasons_map_to_kinds() {
    let kind = |code, reason: &str| {
        ObjectsError::from_rpc(
            code,
            "m".into(),
            Some(Value::Object(vec![(
                "reason".into(),
                Value::Text(reason.into()),
            )])),
        )
        .kind
    };
    for r in [
        "always-refused",
        "not-allowed",
        "needs-listing",
        "authorize",
        "not-permitted",
        "gone",
    ] {
        assert_eq!(kind(-32003, r), ErrorKind::Refused, "{r}");
    }
    assert_eq!(kind(-32002, "limit"), ErrorKind::Limit);
    assert_eq!(kind(-32602, "no-such-root"), ErrorKind::NotFound);
    assert_eq!(kind(-32602, "bad-request"), ErrorKind::Invalid);
    for r in ["bad-path", "not-a-function", "not-an-event-source"] {
        assert_eq!(kind(-32000, r), ErrorKind::NotFound, "{r}");
    }
    assert_eq!(kind(-32000, "threw"), ErrorKind::Failed);
    assert_eq!(kind(-32000, "closed"), ErrorKind::Closed);
    assert_eq!(kind(-32601, ""), ErrorKind::Unsupported);
    let e = ObjectsError::from_rpc(-32003, "refused".into(), None);
    assert_eq!((e.kind, e.reason), (ErrorKind::Refused, None));
}

// ── a scripted host ──

#[tokio::test]
async fn open_reads_the_roots_and_the_features_and_a_missing_list_is_none() {
    let (objects, _host) = open(&["window", "store"], Some(&["events", "handles"])).await;
    assert_eq!(objects.roots(), ["window", "store"]);
    assert!(objects.has_feature("events") && objects.has_feature("handles"));
    assert!(!objects.has_feature("callbacks"));
    let (old, _h) = open(&["window"], None).await;
    assert!(
        old.features().is_empty(),
        "a host that says nothing supports nothing"
    );
    let e = old.root("other").unwrap_err();
    assert_eq!(
        (e.kind, e.reason.as_deref()),
        (ErrorKind::NotFound, Some("no-such-root"))
    );
}

#[tokio::test]
async fn a_get_is_one_resolve_with_the_chain_and_bytes_come_back_as_bytes() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let call = tokio::spawn(async move {
        window
            .resolve(
                Chain::new()
                    .get("app")
                    .call("getCart", vec![Value::Int(1), Value::Bytes(vec![9])])
                    .get("items"),
            )
            .await
    });
    let req = host.request().await;
    assert_eq!(req.method, "resolve");
    assert_eq!(cbor_text(&req.params, "root"), Some("window"));
    let Some(Cbor::Array(ops)) = cbor_get(&req.params, "ops") else {
        panic!("ops");
    };
    assert_eq!(ops.len(), 3, "the whole chain is one request");
    assert_eq!(cbor_text(&ops[0], "get"), Some("app"));
    assert_eq!(cbor_text(&ops[1], "call"), Some("getCart"));
    assert_eq!(
        cbor_get(&ops[1], "args"),
        Some(&Cbor::Array(vec![int(1), Cbor::Bytes(vec![9])]))
    );
    assert_eq!(cbor_text(&ops[2], "get"), Some("items"));
    host.reply(
        req.id,
        cmap(&[("v", cmap(&[("raw", Cbor::Bytes(vec![1, 2, 3]))]))]),
    );
    let reply = call.await.unwrap().unwrap();
    assert_eq!(
        reply.value().unwrap().member("raw"),
        Some(&Value::Bytes(vec![1, 2, 3]))
    );
}

#[tokio::test]
async fn a_name_for_what_is_not_plain_data_is_a_nonvalue_with_the_hosts_own_text() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let call = tokio::spawn(async move { window.get("fn").await });
    let req = host.request().await;
    host.reply(
        req.id,
        cmap(&[("u", t("function")), ("type", t("evil\u{1b}[31m"))]),
    );
    match call.await.unwrap().unwrap() {
        Reply::NonValue(n) => {
            assert_eq!(n.kind, "function");
            assert_eq!(n.type_name.as_deref(), Some("evil\u{1b}[31m"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn set_describe_and_snapshot_send_their_shapes() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let w = window.clone();
    let set = tokio::spawn(async move { w.set("document.title", Value::from("Paid")).await });
    let req = host.request().await;
    assert_eq!(req.method, "set");
    assert_eq!(
        cbor_get(&req.params, "path"),
        Some(&texts(&["document", "title"]))
    );
    assert_eq!(cbor_get(&req.params, "value"), Some(&t("Paid")));
    host.reply(req.id, cmap(&[("ok", Cbor::Bool(true))]));
    set.await.unwrap().unwrap();

    let w = window.clone();
    let d = tokio::spawn(async move { w.describe("app").await });
    let req = host.request().await;
    assert_eq!(req.method, "describe");
    host.reply(
        req.id,
        cmap(&[
            ("type", t("object")),
            (
                "keys",
                Cbor::Array(vec![cmap(&[
                    ("key", t("n")),
                    ("type", t("number")),
                    ("own", Cbor::Bool(true)),
                ])]),
            ),
        ]),
    );
    let d = d.await.unwrap().unwrap();
    assert_eq!(d.type_name, "object");
    assert_eq!(
        d.keys,
        vec![KeyInfo {
            key: "n".into(),
            type_name: "number".into(),
            own: true
        }]
    );

    let w = window.clone();
    let s = tokio::spawn(async move {
        w.snapshot(
            "app",
            SnapshotOptions {
                depth: Some(2),
                max_bytes: Some(4096),
            },
        )
        .await
    });
    let req = host.request().await;
    assert_eq!(req.method, "snapshot");
    assert_eq!(cbor_get(&req.params, "depth"), Some(&int(2)));
    assert_eq!(cbor_get(&req.params, "maxBytes"), Some(&int(4096)));
    host.reply(
        req.id,
        cmap(&[
            ("v", cmap(&[("a", Cbor::Null)])),
            ("truncated", Cbor::Bool(true)),
        ]),
    );
    let s = s.await.unwrap().unwrap();
    assert!(s.truncated);
}

#[tokio::test]
async fn the_hosts_refusal_keeps_its_reason_and_text() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let call = tokio::spawn(async move { window.get("constructor").await });
    let req = host.request().await;
    host.refuse(
        req.id,
        -32003,
        "always-refused",
        "refused: \"constructor\" is never reachable",
    );
    let e = call.await.unwrap().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused);
    assert_eq!(e.reason.as_deref(), Some("always-refused"));
    assert_eq!(e.code, -32003);
}

#[tokio::test]
async fn a_bad_segment_is_refused_before_anything_is_sent() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let e = window.get("a..b").await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Invalid);
    let e = window.set(Path::new(), Value::Null).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Invalid);
    assert!(host.quiet().await, "nothing was written");
}

#[tokio::test]
async fn events_need_the_feature_and_a_host_without_it_is_refused_locally_by_name() {
    let (objects, mut host) = open(&["window"], Some(&["handles"])).await;
    let window = objects.root("window").unwrap();
    let e = window
        .subscribe("bus", "ready", SubscribeOptions::default())
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported);
    assert!(e.message.contains("\"events\""), "{}", e.message);
    assert!(host.quiet().await, "the host never saw it");
}

#[tokio::test]
async fn a_handle_from_a_host_that_did_not_state_handles_is_refused() {
    let (objects, mut host) = open(&["window"], Some(&["events"])).await;
    let window = objects.root("window").unwrap();
    let call = tokio::spawn(async move { window.get("thing").await });
    let req = host.request().await;
    host.reply(req.id, cmap(&[("h", t("abc")), ("kind", t("object"))]));
    let e = call.await.unwrap().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported);
    assert!(e.message.contains("handles"));
}

#[tokio::test]
async fn events_arrive_in_a_bounded_queue_and_both_kinds_of_drop_are_told() {
    let (objects, mut host) = open(&["window"], Some(&["events"])).await;
    let window = objects.root("window").unwrap();
    let sub = tokio::spawn({
        let window = window.clone();
        async move {
            window
                .subscribe(
                    "bus",
                    "tick",
                    SubscribeOptions {
                        capacity: 2,
                        fields: vec!["detail".into()],
                    },
                )
                .await
        }
    });
    let req = host.request().await;
    assert_eq!(req.method, "subscribe");
    assert_eq!(cbor_text(&req.params, "root"), Some("window"));
    assert_eq!(cbor_text(&req.params, "type"), Some("tick"));
    assert_eq!(cbor_get(&req.params, "path"), Some(&texts(&["bus"])));
    assert_eq!(cbor_get(&req.params, "fields"), Some(&texts(&["detail"])));
    let id = cbor_u64(&req.params, "id").unwrap();
    host.reply(req.id, cmap(&[("ok", Cbor::Bool(true))]));
    let mut sub = sub.await.unwrap().unwrap();

    // The queue holds two; the reader reads none. Events 3 and 4 do not fit.
    host.event(id, 1, None, cmap(&[("type", t("tick"))]));
    host.event(id, 2, Some(5), cmap(&[("type", t("tick"))]));
    host.event(id, 3, Some(2), cmap(&[("type", t("tick"))]));
    host.event(id, 4, None, cmap(&[("type", t("tick"))]));
    // wait until the client has taken all four in
    for _ in 0..200 {
        if sub.pending_dropped_here() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(sub.pending_dropped_here(), 2);
    assert_eq!(
        sub.pending_dropped_by_host(),
        2,
        "the host's own count rides on a dropped event too"
    );
    let one = sub.recv().await.unwrap();
    let two = sub.recv().await.unwrap();
    assert_eq!((one.seq, one.dropped_by_host, one.dropped_here), (1, 0, 0));
    assert_eq!((two.seq, two.dropped_by_host, two.dropped_here), (2, 5, 0));
    // the next one that fits is told what was lost before it
    host.event(id, 5, Some(1), cmap(&[("type", t("tick"))]));
    let five = sub.recv().await.unwrap();
    assert_eq!(
        (five.seq, five.dropped_by_host, five.dropped_here),
        (5, 3, 2)
    );
    // a subscription id the client does not have is noise
    host.event(99, 1, None, Cbor::Null);
    // and ending it tells the host
    let end = tokio::spawn(async move { sub.unsubscribe().await });
    let req = host.request().await;
    assert_eq!(req.method, "unsubscribe");
    assert_eq!(cbor_u64(&req.params, "id"), Some(id));
    host.reply(
        req.id,
        cmap(&[("ok", Cbor::Bool(true)), ("dropped", int(4))]),
    );
    assert_eq!(end.await.unwrap().unwrap(), 4);
}

#[tokio::test]
async fn a_handle_is_used_across_calls_and_released_once() {
    let (objects, mut host) = open(&["window"], Some(&["handles"])).await;
    let window = objects.root("window").unwrap();
    let get = tokio::spawn({
        let window = window.clone();
        async move { window.call("app.getCart", vec![]).await }
    });
    let req = host.request().await;
    host.reply(
        req.id,
        cmap(&[
            ("h", t("H1")),
            ("kind", t("object")),
            ("type", t("Cart")),
            ("preview", cmap(&[("keys", texts(&["items", "total"]))])),
        ]),
    );
    let Reply::Handle(handle) = get.await.unwrap().unwrap() else {
        panic!("a handle");
    };
    assert_eq!(
        (handle.kind(), handle.type_name()),
        ("object", Some("Cart"))
    );
    assert_eq!(handle.preview_keys(), ["items", "total"]);
    assert!(!format!("{handle:?}").contains("H1"), "the id is not shown");

    // two operations through it, each naming the handle and not a root
    for method in ["get", "describe"] {
        let target = handle.target();
        let task = tokio::spawn(async move {
            if method == "get" {
                target.get("total").await.map(|_| ())
            } else {
                target.describe(()).await.map(|_| ())
            }
        });
        let req = host.request().await;
        assert_eq!(cbor_text(&req.params, "handle"), Some("H1"));
        assert!(cbor_get(&req.params, "root").is_none());
        if method == "get" {
            host.reply(req.id, cmap(&[("v", int(3))]));
        } else {
            host.reply(
                req.id,
                cmap(&[("type", t("object")), ("keys", Cbor::Array(vec![]))]),
            );
        }
        task.await.unwrap().unwrap();
    }

    // events cannot be made through a handle
    let e = handle
        .target()
        .subscribe("x", "y", SubscribeOptions::default())
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported);

    let rel = tokio::spawn({
        let handle = handle.clone();
        async move {
            handle.release().await?;
            handle.release().await // the second does nothing
        }
    });
    let req = host.request().await;
    assert_eq!(req.method, "release");
    assert_eq!(cbor_text(&req.params, "handle"), Some("H1"));
    host.reply(req.id, cmap(&[("ok", Cbor::Bool(true))]));
    rel.await.unwrap().unwrap();
    assert!(handle.is_released());
    // used after release: refused here
    let e = handle.target().get("total").await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Invalid);
    assert!(host.quiet().await);
}

#[tokio::test]
async fn dropping_the_last_reference_to_a_handle_releases_it() {
    let (objects, mut host) = open(&["window"], Some(&["handles"])).await;
    let window = objects.root("window").unwrap();
    let get = tokio::spawn(async move { window.get("thing").await });
    let req = host.request().await;
    host.reply(req.id, cmap(&[("h", t("H9")), ("kind", t("function"))]));
    let reply = get.await.unwrap().unwrap();
    drop(reply);
    let req = host.request().await;
    assert_eq!(req.method, "release");
    assert_eq!(cbor_text(&req.params, "handle"), Some("H9"));
}

#[tokio::test]
async fn the_end_of_the_channel_fails_what_waits_and_tells_the_hosts_reason() {
    let (objects, mut host) = open(&["window"], Some(&[])).await;
    let window = objects.root("window").unwrap();
    let waiting = tokio::spawn(async move { window.get("slow").await });
    let _ = host.request().await;
    host.notify("closing", cmap(&[("reason", t("page navigated"))]));
    host.inbound.on_close();
    let e = waiting.await.unwrap().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Closed);
    assert!(e.message.contains("page navigated"), "{}", e.message);
    assert_eq!(objects.closing_reason().as_deref(), Some("page navigated"));
    assert!(objects.is_closed());
    let e = objects.root("window").unwrap().get("x").await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Closed);
}

#[tokio::test]
async fn a_request_the_host_never_answers_times_out() {
    let tc = test_channel(1024 * 1024, true);
    let mut host = Host {
        inbound: tc.inbound,
        actions: tc.actions,
        decoder: CborSequenceDecoder::new(1024 * 1024),
        queued: VecDeque::new(),
        closed: false,
    };
    let opening = tokio::spawn(ObjectsClient::from_channel(
        tc.channel,
        OpenOptions {
            timeout: Duration::from_millis(100),
        },
    ));
    let req = host.request().await;
    host.reply(req.id, cmap(&[("roots", texts(&["window"]))]));
    let objects = opening.await.unwrap().unwrap();
    let e = objects.root("window").unwrap().get("x").await.unwrap_err();
    assert_eq!(
        (e.kind, e.reason.as_deref()),
        (ErrorKind::Failed, Some("timeout"))
    );
}

#[tokio::test]
async fn a_host_that_makes_a_request_of_the_client_is_told_there_is_no_such_method() {
    let (_objects, mut host) = open(&["window"], Some(&[])).await;
    host.write(cmap(&[
        ("jsonrpc", t("2.0")),
        ("id", int(77)),
        ("method", t("callback")),
    ]));
    let answer = host.next().await;
    assert_eq!(cbor_u64(&answer, "id"), Some(77));
    assert_eq!(
        cbor_get(&answer, "error").and_then(|e| cbor_get(e, "code")),
        Some(&int(-32601))
    );
}
