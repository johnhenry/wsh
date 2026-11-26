//! The client's gateway hub against a scripted host: the frames it sends are decoded and the
//! host's answers are fed back through `on_message`, exactly as the dispatch loop does.

use super::*;
use std::time::Duration;
use tokio::io::duplex;
use wsh_core::decode_envelope;

struct Host {
    hub: Arc<GatewayHub>,
    frames: mpsc::Receiver<Vec<u8>>,
}

fn host(credit: bool) -> Host {
    let (tx, frames) = mpsc::channel(256);
    let hub = Arc::new(GatewayHub::new(tx));
    hub.set_credit(credit);
    Host { hub, frames }
}

impl Host {
    async fn sent(&mut self) -> Envelope {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.frames.recv())
            .await
            .expect("timed out waiting for a frame")
            .expect("hub dropped");
        decode_envelope(&frame[4..]).unwrap()
    }

    async fn sent_within(&mut self, ms: u64) -> Option<Envelope> {
        let frame = tokio::time::timeout(Duration::from_millis(ms), self.frames.recv())
            .await
            .ok()??;
        Some(decode_envelope(&frame[4..]).unwrap())
    }

    /// What the host does on the wire.
    async fn deliver(&self, payload: Payload, msg_type: MsgType) -> bool {
        self.hub.on_message(&Envelope { msg_type, payload }).await
    }

    async fn ok(&self, id: u32) {
        assert!(
            self.deliver(
                Payload::GatewayOk(GatewayOkPayload {
                    gateway_id: id,
                    resolved_addr: Some("127.0.0.1".into()),
                }),
                MsgType::GatewayOk
            )
            .await
        );
    }

    async fn data(&self, id: u32, data: &[u8]) {
        self.deliver(
            Payload::GatewayData(GatewayDataPayload {
                gateway_id: id,
                data: data.to_vec(),
            }),
            MsgType::GatewayData,
        )
        .await;
    }

    async fn credit(&self, id: u32, bytes: u32) {
        self.deliver(
            Payload::GatewayCredit(GatewayCreditPayload {
                gateway_id: id,
                bytes,
            }),
            MsgType::GatewayCredit,
        )
        .await;
    }

    async fn close(&self, id: u32) {
        self.deliver(
            Payload::GatewayClose(GatewayClosePayload {
                gateway_id: id,
                reason: None,
            }),
            MsgType::GatewayClose,
        )
        .await;
    }
}

/// Open a connection and answer it; returns the stream and its id.
async fn open(h: &mut Host) -> GatewayStream {
    let hub = h.hub.clone();
    let opener = tokio::spawn(async move { hub.open(|id| open_tcp_msg(id, "db", 5432)).await });
    let id = match h.sent().await.payload {
        Payload::OpenTcp(o) => {
            assert_eq!((o.host.as_str(), o.port), ("db", 5432));
            o.gateway_id
        }
        other => panic!("{other:?}"),
    };
    h.ok(id).await;
    opener.await.unwrap().unwrap()
}

#[tokio::test]
async fn an_open_that_the_host_refuses_says_why() {
    let mut h = host(true);
    let hub = h.hub.clone();
    let opener = tokio::spawn(async move { hub.open(|id| open_tcp_msg(id, "x", 1)).await });
    let id = match h.sent().await.payload {
        Payload::OpenTcp(o) => o.gateway_id,
        other => panic!("{other:?}"),
    };
    assert!(
        h.deliver(
            Payload::GatewayFail(GatewayFailPayload {
                gateway_id: id,
                code: 4,
                message: "destination not allowed".into(),
            }),
            MsgType::GatewayFail
        )
        .await
    );
    let err = opener.await.unwrap().err().unwrap().to_string();
    assert!(
        err.contains("destination not allowed") && err.contains("policy"),
        "{err}"
    );
}

#[tokio::test]
async fn data_that_arrives_with_the_ok_is_not_lost() {
    // GatewayOk and GatewayData in one burst: the dispatch loop handles them back to back, before
    // the opener task has run.
    let mut h = host(true);
    let hub = h.hub.clone();
    let opener = tokio::spawn(async move { hub.open(|id| open_unix_msg(id, "/s")).await });
    let id = match h.sent().await.payload {
        Payload::OpenUnix(o) => o.gateway_id,
        other => panic!("{other:?}"),
    };
    h.ok(id).await;
    h.data(id, b"banner").await;
    let s = opener.await.unwrap().unwrap();
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"banner");
}

#[tokio::test]
async fn reads_come_in_pieces_and_end_when_the_host_closes() {
    let mut h = host(true);
    let s = open(&mut h).await;
    h.data(s.id(), b"abcdef").await;
    let mut two = [0u8; 2];
    assert_eq!(s.read(&mut two).await.unwrap(), 2);
    assert_eq!(&two, b"ab");
    let mut big = [0u8; 100];
    let n = s.read(&mut big).await.unwrap();
    assert_eq!(&big[..n], b"cdef");
    h.close(s.id()).await;
    assert_eq!(s.read(&mut big).await.unwrap(), 0, "end of stream");
}

#[tokio::test]
async fn a_close_that_arrives_with_unread_data_still_delivers_it() {
    let mut h = host(true);
    let s = open(&mut h).await;
    h.data(s.id(), b"last words").await;
    h.close(s.id()).await;
    let mut buf = [0u8; 32];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"last words");
    assert_eq!(s.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn writes_wait_for_credit_and_resume_when_it_comes() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let writer = {
        let s = s.clone();
        tokio::spawn(async move { s.write_all(&vec![7u8; GATEWAY_CREDIT_WINDOW + 1000]).await })
    };
    // The host reads nothing and returns no credit: exactly the window gets sent.
    let mut sent = 0usize;
    while let Some(m) = h.sent_within(300).await {
        if let Payload::GatewayData(d) = m.payload {
            sent += d.data.len();
        }
    }
    assert_eq!(sent, GATEWAY_CREDIT_WINDOW);
    assert!(!writer.is_finished(), "the writer waits");
    h.credit(s.id(), 1000).await;
    writer.await.unwrap().unwrap();
    let mut more = 0usize;
    while let Some(m) = h.sent_within(100).await {
        if let Payload::GatewayData(d) = m.payload {
            more += d.data.len();
        }
    }
    assert_eq!(more, 1000);
}

#[tokio::test]
async fn writes_do_not_wait_when_credit_was_not_negotiated() {
    let mut h = host(false);
    let s = open(&mut h).await;
    assert!(!s.credit_negotiated());
    // Far more than the window; it all goes out (the transport queue is the only limit).
    s.write_all(&vec![1u8; 200_000]).await.unwrap();
    let mut sent = 0usize;
    while let Some(m) = h.sent_within(100).await {
        if let Payload::GatewayData(d) = m.payload {
            sent += d.data.len();
        }
    }
    assert_eq!(sent, 200_000);
    // And credit messages are ignored.
    h.credit(s.id(), 5).await;
}

#[tokio::test]
async fn a_blocked_writer_fails_when_the_connection_is_destroyed() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let writer = {
        let s = s.clone();
        tokio::spawn(async move { s.write_all(&vec![0u8; GATEWAY_CREDIT_WINDOW * 2]).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.destroy();
    let r = tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .expect("writer stuck")
        .unwrap();
    assert!(r.is_err());
}

#[tokio::test]
async fn credit_goes_back_as_the_application_reads() {
    let mut h = host(true);
    let s = open(&mut h).await;
    h.data(s.id(), &vec![9u8; GATEWAY_CREDIT_WINDOW / 2]).await;
    let mut buf = vec![0u8; GATEWAY_CREDIT_WINDOW];
    // Nothing is returned before the application has taken the data.
    assert!(h.sent_within(100).await.is_none());
    let mut got = 0;
    while got < GATEWAY_CREDIT_WINDOW / 2 {
        got += s.read(&mut buf).await.unwrap();
    }
    match h.sent().await.payload {
        Payload::GatewayCredit(c) => assert_eq!(c.bytes as usize, GATEWAY_CREDIT_WINDOW / 2),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_host_that_exceeds_the_credit_it_was_given_is_closed_on() {
    let mut h = host(true);
    let s = open(&mut h).await;
    for _ in 0..5 {
        h.data(s.id(), &vec![0u8; 60 * 1024]).await;
    }
    assert!(s.is_closed());
    // The host is told.
    let mut closed = false;
    while let Some(m) = h.sent_within(100).await {
        if let Payload::GatewayClose(c) = m.payload {
            assert_eq!(c.reason.as_deref(), Some("host exceeded its credit"));
            closed = true;
        }
    }
    assert!(closed);
    let mut buf = [0u8; 8];
    assert!(s.read(&mut buf).await.is_err());
}

#[tokio::test]
async fn without_credit_unread_data_is_bounded_per_connection() {
    let mut h = host(false);
    let s = open(&mut h).await;
    // The application never reads; the host keeps sending.
    for _ in 0..80 {
        h.data(s.id(), &vec![0u8; 64 * 1024]).await;
    }
    assert!(s.is_closed(), "the cap closed it");
    assert_eq!(
        h.hub.budget.load(Ordering::Acquire),
        0,
        "and gave its bytes back"
    );
}

#[tokio::test]
async fn without_credit_unread_data_is_bounded_across_connections() {
    let mut h = host(false);
    let mut streams = Vec::new();
    for _ in 0..12 {
        streams.push(open(&mut h).await);
    }
    // 12 connections x 3.5 MiB would be 42 MiB unread; the per-client cap is 32 MiB.
    'outer: for _ in 0..56 {
        for s in &streams {
            h.data(s.id(), &vec![0u8; 64 * 1024]).await;
        }
        if streams.iter().any(|s| s.is_closed()) {
            break 'outer;
        }
    }
    assert!(streams.iter().any(|s| s.is_closed()));
    assert!(h.hub.budget.load(Ordering::Acquire) <= MAX_QUEUED_TOTAL);
}

#[tokio::test]
async fn shutdown_half_closes_once_and_the_host_can_still_answer() {
    let mut h = host(true);
    let s = open(&mut h).await;
    s.shutdown().await;
    s.shutdown().await;
    match h.sent().await.payload {
        Payload::GatewayClose(c) => assert_eq!(c.gateway_id, s.id()),
        other => panic!("{other:?}"),
    }
    assert!(h.sent_within(100).await.is_none(), "only one GatewayClose");
    assert!(s.write_all(b"x").await.is_err(), "no more writing");
    h.data(s.id(), b"reply").await;
    let mut buf = [0u8; 8];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"reply");
    h.close(s.id()).await;
    assert_eq!(s.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn dropping_a_stream_closes_it() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    drop(s);
    match h.sent().await.payload {
        Payload::GatewayClose(c) => assert_eq!(c.gateway_id, id),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_late_ok_for_an_abandoned_open_is_closed_again() {
    let mut h = host(true);
    // An Ok for an id nobody is waiting for.
    assert!(
        h.deliver(
            Payload::GatewayOk(GatewayOkPayload {
                gateway_id: 41,
                resolved_addr: None
            }),
            MsgType::GatewayOk
        )
        .await
    );
    match h.sent().await.payload {
        Payload::GatewayClose(c) => assert_eq!(c.gateway_id, 41),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn messages_for_nothing_this_client_opened_are_left_alone() {
    let h = host(true);
    assert!(
        !h.deliver(
            Payload::GatewayData(GatewayDataPayload {
                gateway_id: 9,
                data: vec![1]
            }),
            MsgType::GatewayData
        )
        .await
    );
    assert!(
        !h.deliver(
            Payload::GatewayFail(GatewayFailPayload {
                gateway_id: 9,
                code: 1,
                message: String::new()
            }),
            MsgType::GatewayFail
        )
        .await
    );
}

#[tokio::test]
async fn pump_joins_a_local_stream_both_ways_and_passes_the_half_close_on() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, mut app) = duplex(1 << 16);
    let pump = tokio::spawn(s.pump(local));

    app.write_all(b"GET /").await.unwrap();
    // The application closes its write side after the request (a half-close).
    let mut sent = Vec::new();
    while sent.len() < 5 {
        if let Payload::GatewayData(d) = h.sent().await.payload {
            sent.extend(d.data);
        }
    }
    assert_eq!(sent, b"GET /");
    app.shutdown().await.unwrap();
    match h.sent().await.payload {
        Payload::GatewayClose(c) => assert_eq!(c.gateway_id, id),
        other => panic!("{other:?}"),
    }
    // The host still answers, then closes: the application sees the answer and the end.
    h.data(id, b"200 OK").await;
    h.close(id).await;
    let mut got = Vec::new();
    app.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"200 OK");
    let (up, down) = pump.await.unwrap().unwrap();
    assert_eq!((up, down), (5, 6));
}

// ── a half-close does not end the other direction (#271) ──────────

#[tokio::test]
async fn a_host_that_closed_first_does_not_stop_what_the_local_side_sends_later() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, mut app) = duplex(1 << 16);
    let pump = tokio::spawn(s.pump(local));
    h.data(id, b"bye").await;
    h.close(id).await;
    // The application reads the answer and its end of file, then (1.5 s later, past the old limits) sends.
    let mut got = [0u8; 3];
    app.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"bye");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!pump.is_finished(), "the exchange is still open");
    app.write_all(b"late").await.unwrap();
    let mut sent = Vec::new();
    while sent.len() < 4 {
        if let Payload::GatewayData(d) = h.sent().await.payload {
            sent.extend(d.data);
        }
    }
    assert_eq!(sent, b"late");
    app.shutdown().await.unwrap();
    let (up, down) = pump.await.unwrap().unwrap();
    assert_eq!((up, down), (4, 3));
}

#[tokio::test]
async fn a_host_that_discarded_the_connection_ends_our_direction_too_and_dropping_says_so() {
    let mut h = host(true);
    let s = open(&mut h).await;
    h.deliver(
        Payload::GatewayClose(GatewayClosePayload {
            gateway_id: s.id(),
            reason: Some(GATEWAY_DISCARDED.into()),
        }),
        MsgType::GatewayClose,
    )
    .await;
    assert!(s.write_all(b"x").await.is_err(), "nobody reads any more");
    let t = open(&mut h).await;
    let id = t.id();
    drop(t);
    match h.sent().await.payload {
        Payload::GatewayClose(c) => {
            assert_eq!(c.gateway_id, id);
            assert_eq!(c.reason.as_deref(), Some(GATEWAY_DISCARDED));
        }
        other => panic!("{other:?}"),
    }
}

// ── a destroy after our own half-close is told to the host ────────

/// A GatewayClose the host sends for `id`, with a reason or none.
async fn host_close(h: &Host, id: u32, reason: Option<&str>) {
    h.deliver(
        Payload::GatewayClose(GatewayClosePayload {
            gateway_id: id,
            reason: reason.map(str::to_string),
        }),
        MsgType::GatewayClose,
    )
    .await;
}

/// The next frame must be a GatewayClose for `id` with this reason.
async fn expect_close(h: &mut Host, id: u32, reason: Option<&str>) {
    match h.sent().await.payload {
        Payload::GatewayClose(c) => {
            assert_eq!(c.gateway_id, id);
            assert_eq!(c.reason.as_deref(), reason);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn destroying_after_a_half_close_sends_a_second_close_saying_discarded_once() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    s.shutdown().await;
    expect_close(&mut h, id, None).await;
    s.destroy();
    expect_close(&mut h, id, Some(GATEWAY_DISCARDED)).await;
    s.destroy();
    drop(s);
    assert!(h.sent_within(100).await.is_none(), "only once");
}

#[tokio::test]
async fn dropping_a_half_closed_stream_says_discarded() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    s.shutdown().await;
    expect_close(&mut h, id, None).await;
    drop(s);
    expect_close(&mut h, id, Some(GATEWAY_DISCARDED)).await;
}

#[tokio::test]
async fn destroying_after_both_sides_closed_sends_nothing_more() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    s.shutdown().await;
    expect_close(&mut h, id, None).await;
    host_close(&h, id, None).await;
    s.destroy();
    drop(s);
    assert!(h.sent_within(100).await.is_none());
}

#[tokio::test]
async fn a_second_discarded_close_from_the_host_ends_the_connection_and_nothing_goes_back() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    host_close(&h, id, None).await; // a plain half-close: we may go on sending
    s.write_all(b"x").await.unwrap();
    let _ = h.sent().await;
    assert!(!s.is_closed());
    host_close(&h, id, Some(GATEWAY_DISCARDED)).await; // its reader is gone
    assert!(s.is_closed());
    assert!(s.write_all(b"y").await.is_err());
    let mut buf = [0u8; 4];
    assert_eq!(s.read(&mut buf).await.unwrap(), 0);
    drop(s);
    assert!(
        h.sent_within(100).await.is_none(),
        "it reads nothing more: no answer"
    );
}

#[tokio::test]
async fn a_repeated_close_without_the_reason_changes_nothing() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    host_close(&h, id, None).await;
    host_close(&h, id, None).await;
    host_close(&h, id, Some("idle timeout")).await;
    assert!(!s.is_closed());
    s.write_all(b"still open").await.unwrap();
}

#[tokio::test]
async fn a_local_stream_that_goes_away_after_the_half_close_is_told_to_the_host() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, mut app) = duplex(1 << 16);
    let pump = tokio::spawn(s.pump_with_idle(local, None));
    // The application sends its request, half-closes and goes away without reading.
    app.shutdown().await.unwrap();
    expect_close(&mut h, id, None).await;
    drop(app);
    // The host's answer finds nobody: the write to the local side fails, and the host is told.
    h.data(id, b"answer").await;
    expect_close(&mut h, id, Some(GATEWAY_DISCARDED)).await;
    let _ = pump.await.unwrap();
}

#[tokio::test]
async fn a_stream_can_still_write_after_the_hosts_close() {
    let mut h = host(true);
    let s = open(&mut h).await;
    h.close(s.id()).await;
    let mut buf = [0u8; 4];
    assert_eq!(s.read(&mut buf).await.unwrap(), 0);
    s.write_all(b"still here").await.unwrap();
    match h.sent().await.payload {
        Payload::GatewayData(d) => assert_eq!(d.data, b"still here"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_half_closed_pump_with_nothing_moving_is_ended_by_the_idle_bound_not_sooner() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, app) = duplex(1 << 16);
    let idle = Duration::from_millis(900);
    let t0 = std::time::Instant::now();
    let pump = tokio::spawn(s.pump_with_idle(local, Some(idle)));
    h.close(id).await; // the host half-closes; the local side stays open and quiet
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!pump.is_finished(), "not sooner than the bound");
    let result = tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the idle bound must end a quiet half-closed exchange")
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(t0.elapsed() >= idle);
    drop(app);
}

#[tokio::test]
async fn local_bytes_keep_a_half_closed_pump_alive_past_the_idle_bound() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, mut app) = duplex(1 << 16);
    let pump = tokio::spawn(s.pump_with_idle(local, Some(Duration::from_millis(700))));
    h.close(id).await;
    // A byte every 300 ms for 1.8 s: more than twice the bound, but never quiet for the bound.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        app.write_all(b"x").await.unwrap();
        assert!(!pump.is_finished());
    }
    app.shutdown().await.unwrap();
    let (up, _) = pump.await.unwrap().unwrap();
    assert_eq!(up, 6);
}

#[tokio::test]
async fn without_an_idle_bound_a_quiet_half_closed_pump_stays() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let id = s.id();
    let (local, app) = duplex(1 << 16);
    let pump = tokio::spawn(s.pump_with_idle(local, None));
    h.close(id).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!pump.is_finished());
    pump.abort();
    drop(app);
}

#[tokio::test]
async fn a_pump_ends_when_the_connection_is_destroyed_whatever_the_local_side_does() {
    let mut h = host(true);
    let s = open(&mut h).await;
    let (local, app) = duplex(1 << 16);
    let victim = s.clone();
    let pump = tokio::spawn(s.pump(local));
    victim.destroy();
    let done = tokio::time::timeout(Duration::from_secs(3), pump).await;
    assert!(done.is_ok(), "a destroyed connection has nobody to feed");
    drop(app);
}

#[tokio::test]
async fn a_listener_hands_out_inbound_connections() {
    let mut h = host(true);
    let hub = h.hub.clone();
    let opener = tokio::spawn(async move {
        hub.listen(|id| listen_unix_msg(id, "/run/x.sock", false))
            .await
    });
    let lid = match h.sent().await.payload {
        Payload::ListenUnix(l) => {
            assert_eq!(l.path, "/run/x.sock");
            assert_eq!(l.replace, None, "replace is left out unless asked for");
            l.listener_id
        }
        other => panic!("{other:?}"),
    };
    assert!(
        h.deliver(
            Payload::ListenOk(ListenOkPayload {
                listener_id: lid,
                actual_port: 0
            }),
            MsgType::ListenOk
        )
        .await
    );
    let mut listener = opener.await.unwrap().unwrap();

    h.deliver(
        Payload::InboundOpen(InboundOpenPayload {
            listener_id: lid,
            channel_id: 5,
            peer_addr: "unix".into(),
            peer_port: 0,
        }),
        MsgType::InboundOpen,
    )
    .await;
    let pending = listener.next().await.unwrap();
    assert_eq!(pending.channel_id, 5);
    let stream = pending.accept().await.unwrap();
    match h.sent().await.payload {
        Payload::InboundAccept(a) => {
            assert_eq!((a.channel_id, a.gateway_id), (5, Some(stream.id())))
        }
        other => panic!("{other:?}"),
    }
    h.data(stream.id(), b"hi").await;
    let mut buf = [0u8; 4];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hi");

    listener.close().await;
    match h.sent().await.payload {
        Payload::ListenClose(c) => assert_eq!(c.listener_id, lid),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_refused_listen_says_why() {
    let mut h = host(true);
    let hub = h.hub.clone();
    let opener =
        tokio::spawn(async move { hub.listen(|id| listen_unix_msg(id, "/x", true)).await });
    let lid = match h.sent().await.payload {
        Payload::ListenUnix(l) => {
            assert_eq!(l.replace, Some(true));
            l.listener_id
        }
        other => panic!("{other:?}"),
    };
    h.deliver(
        Payload::ListenFail(ListenFailPayload {
            listener_id: lid,
            reason: "address in use".into(),
        }),
        MsgType::ListenFail,
    )
    .await;
    let err = opener.await.unwrap().err().unwrap().to_string();
    assert!(err.contains("address in use"), "{err}");
}

#[tokio::test]
async fn losing_the_host_ends_every_connection() {
    let mut h = host(true);
    let a = open(&mut h).await;
    let b = open(&mut h).await;
    h.hub.close_all();
    let mut buf = [0u8; 4];
    assert!(a.read(&mut buf).await.is_err());
    assert!(b.read(&mut buf).await.is_err());
    assert!(a.write_all(b"x").await.is_err());
}

#[test]
fn endpoint_names_follow_the_spec() {
    for ok in ["docker", "a", "docker.sock", "my-ep_1", &"a".repeat(64)] {
        assert!(valid_endpoint_name(ok), "{ok}");
    }
    for bad in ["", "-x", ".x", "a b", "a/b", "@x", &"a".repeat(65), "é"] {
        assert!(!valid_endpoint_name(bad), "{bad:?}");
    }
}

#[test]
fn a_missing_feature_is_named() {
    let err = require_feature(
        &["mcp".into()],
        GATEWAY_UNIX_FEATURE,
        "unix-socket forwarding",
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("gateway-unix") && err.contains("unix-socket forwarding"),
        "{err}"
    );
    assert!(require_feature(&["gateway-unix".into()], GATEWAY_UNIX_FEATURE, "x").is_ok());
}

// The GatewayFail code table, shared with the JS side as spec/gateway-fail.vectors.json.
fn gateway_fail_vectors() -> Vec<(u32, String, Option<String>)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/gateway-fail.vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("read spec/gateway-fail.vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("vectors are JSON");
    doc["codes"]
        .as_array()
        .expect("codes array")
        .iter()
        .map(|row| {
            (
                row["code"].as_u64().expect("code") as u32,
                row["name"].as_str().expect("name").to_string(),
                row["alsoSentAs"][0].as_str().map(str::to_string),
            )
        })
        .collect()
}

#[test]
fn gateway_fail_names_match_the_shared_vectors() {
    let rows = gateway_fail_vectors();
    assert_eq!(rows.len(), 8);
    for (code, name, _) in &rows {
        assert_eq!(gateway_fail_name(*code), Some(name.as_str()), "code {code}");
    }
    assert_eq!(gateway_fail_name(0), None);
    assert_eq!(gateway_fail_name(9), None);
}

#[test]
fn every_shared_vector_has_its_own_message() {
    for (code, name, also) in gateway_fail_vectors() {
        if name == "TIMEOUT" {
            // Reported as the client's own timeout error, checked below.
            continue;
        }
        let text = gateway_failure(code, "").to_string();
        assert!(
            !text.contains("gateway failure"),
            "code {code} {name} falls to the generic text: {text}"
        );
        assert!(text.contains(&format!("gateway code {code}")), "{text}");
        if also.is_some() {
            // A 5 may be a timeout from an older Node gateway: the message says both readings.
            assert!(
                text.contains("disabled") && text.contains("older Node gateway"),
                "{text}"
            );
        }
    }
    assert!(gateway_failure(5, "")
        .to_string()
        .contains("the host's gateway is disabled, or a timeout from an older Node gateway"));
    assert!(gateway_failure(6, "").to_string().contains("closed"));
    assert!(gateway_failure(99, "")
        .to_string()
        .contains("gateway failure"));
}

#[test]
fn a_timeout_code_is_the_clients_timeout_error() {
    assert!(matches!(
        gateway_failure(8, "connect timed out"),
        WshError::Timeout
    ));
    // 5 stays a plain failure: the Rust server sends it for "disabled".
    assert!(matches!(
        gateway_failure(5, "gateway disabled"),
        WshError::Other(_)
    ));
}
