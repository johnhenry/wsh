//! The gateway session against real sockets: relays, credit, byte caps, half-close, unix-socket
//! policy and listeners, reverse TCP listeners, isolation between connections.

use super::*;
use crate::gateway::policy::GatewayPolicy;
use crate::gateway::unix_policy::UnixPolicy;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CREDIT: &[&str] = &[GATEWAY_CREDIT_FEATURE];

struct Rig {
    session: GatewaySession,
    rx: mpsc::Receiver<Envelope>,
}

fn rig_with(policy: GatewayPolicy, enabled: bool, features: &[&str]) -> Rig {
    let (tx, rx) = mpsc::channel(64);
    let features: Vec<String> = features.iter().map(|f| f.to_string()).collect();
    let session = GatewaySession::new(
        Arc::new(GatewayPolicyEnforcer::new(policy)),
        tx,
        enabled,
        &features,
    );
    Rig { session, rx }
}

fn loopback_policy() -> GatewayPolicy {
    GatewayPolicy {
        allowed_destinations: vec!["127.0.0.1".into()],
        ..GatewayPolicy::default()
    }
}

fn rig(features: &[&str]) -> Rig {
    rig_with(loopback_policy(), true, features)
}

use crate::gateway::policy::GatewayPolicyEnforcer;

impl Rig {
    async fn next(&mut self) -> Envelope {
        tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
            .await
            .expect("timed out waiting for a message")
            .expect("session closed")
    }

    fn send(&self, msg_type: MsgType, payload: Payload) {
        self.session.handle(Envelope { msg_type, payload });
    }

    fn open_tcp(&self, id: u32, port: u16) {
        self.send(
            MsgType::OpenTcp,
            Payload::OpenTcp(OpenTcpPayload {
                gateway_id: id,
                host: "127.0.0.1".into(),
                port,
            }),
        );
    }

    fn data(&self, id: u32, data: Vec<u8>) {
        self.send(
            MsgType::GatewayData,
            Payload::GatewayData(GatewayDataPayload {
                gateway_id: id,
                data,
            }),
        );
    }

    fn credit(&self, id: u32, bytes: u32) {
        self.send(
            MsgType::GatewayCredit,
            Payload::GatewayCredit(GatewayCreditPayload {
                gateway_id: id,
                bytes,
            }),
        );
    }

    fn close(&self, id: u32) {
        self.send(
            MsgType::GatewayClose,
            Payload::GatewayClose(GatewayClosePayload {
                gateway_id: id,
                reason: None,
            }),
        );
    }

    /// Wait for GatewayOk for `id`.
    async fn expect_ok(&mut self, id: u32) {
        match self.next().await.payload {
            Payload::GatewayOk(ok) => assert_eq!(ok.gateway_id, id),
            other => panic!("expected GatewayOk, got {other:?}"),
        }
    }

    async fn expect_fail(&mut self, id: u32) -> (u32, String) {
        match self.next().await.payload {
            Payload::GatewayFail(f) => {
                assert_eq!(f.gateway_id, id);
                (f.code, f.message)
            }
            other => panic!("expected GatewayFail, got {other:?}"),
        }
    }

    /// Everything that arrives within `ms` (data bytes per id, whether a close came, credit seen).
    async fn drain(&mut self, ms: u64) -> Vec<Envelope> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        while let Ok(Some(m)) = tokio::time::timeout_at(deadline, self.rx.recv()).await {
            out.push(m);
        }
        out
    }
}

fn data_len(msgs: &[Envelope]) -> usize {
    msgs.iter()
        .map(|m| match &m.payload {
            Payload::GatewayData(d) => d.data.len(),
            _ => 0,
        })
        .sum()
}

fn got_close(msgs: &[Envelope]) -> Option<Option<String>> {
    msgs.iter().find_map(|m| match &m.payload {
        Payload::GatewayClose(c) => Some(c.reason.clone()),
        _ => None,
    })
}

async fn echo_service() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// A service that accepts and never reads or writes.
async fn mute_service() -> (u16, tokio::sync::mpsc::UnboundedReceiver<TcpStream>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let _ = tx.send(s);
        }
    });
    (port, rx)
}

/// A service that writes as fast as the peer lets it, forever.
async fn firehose_service() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5au8; 64 * 1024];
                while s.write_all(&chunk).await.is_ok() {}
            });
        }
    });
    port
}

// ── basics ────────────────────────────────────────────────────────

#[tokio::test]
async fn data_goes_both_ways_with_and_without_credit() {
    for features in [CREDIT, &[][..]] {
        let port = echo_service().await;
        let mut r = rig(features);
        r.open_tcp(1, port);
        r.expect_ok(1).await;
        r.data(1, b"hello".to_vec());
        match r.next().await.payload {
            Payload::GatewayData(d) => assert_eq!((d.gateway_id, d.data), (1, b"hello".to_vec())),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn credit_is_used_only_when_the_client_asked_for_it() {
    assert!(rig(CREDIT).session.credit_negotiated());
    assert!(!rig(&[]).session.credit_negotiated());
    assert!(!rig(&["mcp"]).session.credit_negotiated());
    // A disabled gateway never meters, whatever the client lists.
    assert!(!rig_with(loopback_policy(), false, CREDIT)
        .session
        .credit_negotiated());
}

#[tokio::test]
async fn a_disabled_gateway_refuses_with_code_5() {
    let mut r = rig_with(loopback_policy(), false, CREDIT);
    r.open_tcp(7, 1);
    assert_eq!(r.expect_fail(7).await.0, 5);
    r.send(
        MsgType::OpenUnix,
        Payload::OpenUnix(OpenUnixPayload {
            gateway_id: 8,
            path: "/x".into(),
        }),
    );
    assert_eq!(r.expect_fail(8).await.0, 5);
}

#[tokio::test]
async fn gateway_ids_belong_to_one_connection() {
    let port = echo_service().await;
    let mut a = rig(CREDIT);
    let mut b = rig(CREDIT);
    a.open_tcp(1, port);
    b.open_tcp(1, port);
    a.expect_ok(1).await;
    b.expect_ok(1).await;
    // `b` closing its id 1 does not touch `a`'s.
    b.close(1);
    a.data(1, b"still here".to_vec());
    match a.next().await.payload {
        Payload::GatewayData(d) => assert_eq!(d.data, b"still here"),
        other => panic!("{other:?}"),
    }
    // And `b` cannot write to `a`'s connection by guessing its id: it has none of its own.
    let _ = b.drain(50).await;
    b.data(2, b"x".to_vec());
    assert!(b.drain(100).await.is_empty());
}

#[tokio::test]
async fn an_id_in_use_is_refused_and_the_connection_limit_answers_queue_full() {
    let port = echo_service().await;
    let mut r = rig_with(
        GatewayPolicy {
            max_connections: 2,
            ..loopback_policy()
        },
        true,
        CREDIT,
    );
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.open_tcp(1, port);
    assert_eq!(r.expect_fail(1).await.0, 4);
    r.open_tcp(2, port);
    r.expect_ok(2).await;
    r.open_tcp(3, port);
    assert_eq!(r.expect_fail(3).await.0, 7);
    // The slot comes back when a connection ends.
    r.close(2);
    let msgs = r.drain(1500).await;
    assert!(got_close(&msgs).is_some());
    r.open_tcp(3, port);
    r.expect_ok(3).await;
}

// ── flow control ──────────────────────────────────────────────────

#[tokio::test]
async fn a_fast_origin_stops_at_the_credit_when_the_client_stalls() {
    let port = firehose_service().await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    // The client reads everything that arrives but returns no credit.
    let first = r.drain(700).await;
    assert_eq!(
        data_len(&first),
        GATEWAY_CREDIT_WINDOW,
        "a stalled client gets exactly its initial credit and no more"
    );
    let later = r.drain(300).await;
    assert_eq!(data_len(&later), 0, "nothing flows without credit");
    // Credit lets exactly that much more through.
    r.credit(1, 100_000);
    let more = r.drain(500).await;
    assert_eq!(data_len(&more), 100_000);
}

#[tokio::test]
async fn without_credit_a_stalled_client_stops_the_origin_by_backpressure() {
    let port = firehose_service().await;
    let mut r = rig(&[]);
    r.open_tcp(1, port);
    // The first message is GatewayOk; then the client reads nothing for a while.
    r.expect_ok(1).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    // What is queued is bounded by the queue's size (64 frames of at most 64 KiB), not by the
    // origin's speed.
    let mut queued = 0usize;
    while let Ok(m) = r.rx.try_recv() {
        queued += data_len(&[m]);
    }
    assert!(queued <= 65 * 64 * 1024, "queued {queued} bytes");
    assert!(queued > 0);
}

#[tokio::test]
async fn memory_stays_flat_while_a_fast_origin_meets_a_stalled_client() {
    // Resident memory of this test process, sampled while the origin streams at full speed and
    // the client reads nothing for a while.
    fn rss_kib() -> Option<usize> {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    let port = firehose_service().await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let _ = r.drain(300).await;
    let Some(before) = rss_kib() else { return };
    // Seconds of a firehose against a client that grants nothing.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = rss_kib().unwrap();
    let growth_mib = after.saturating_sub(before) / 1024;
    assert!(
        growth_mib < 16,
        "resident memory grew by {growth_mib} MiB while the client was stalled"
    );
}

#[tokio::test]
async fn credit_is_returned_as_the_origin_takes_data() {
    let port = echo_service().await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    // 128 KiB (half the window) taken by the origin earns a GatewayCredit back.
    for _ in 0..2 {
        r.data(1, vec![1u8; 64 * 1024]);
    }
    let msgs = r.drain(500).await;
    let credited: u32 = msgs
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::GatewayCredit(c) if c.gateway_id == 1 => Some(c.bytes),
            _ => None,
        })
        .sum();
    assert!(
        credited >= (GATEWAY_CREDIT_WINDOW / 2) as u32,
        "credited {credited}"
    );
}

#[tokio::test]
async fn a_client_that_exceeds_its_credit_is_closed() {
    let (port, _held) = mute_service().await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    // 5 x 60 KiB = 300 KiB against 256 KiB of credit, to an origin that takes nothing.
    for _ in 0..5 {
        r.data(1, vec![2u8; 60 * 1024]);
    }
    let msgs = r.drain(500).await;
    let reason = got_close(&msgs).expect("the connection should have been closed");
    assert_eq!(reason.as_deref(), Some("peer exceeded its credit"));
    assert_eq!(r.session.open_connections(), 0);
    assert_eq!(r.session.buffered_bytes(), 0, "the budget is given back");
}

#[tokio::test]
async fn without_credit_a_client_that_outruns_its_origin_is_closed_at_the_byte_cap() {
    let (port, _held) = mute_service().await;
    let mut r = rig_with(
        GatewayPolicy {
            max_buffered_bytes: 512 * 1024,
            max_client_buffered_bytes: 2 * 1024 * 1024,
            ..loopback_policy()
        },
        true,
        &[],
    );
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    // The origin reads nothing, so what the kernel will not hold piles up here until the cap.
    let chunk = vec![3u8; 64 * 1024];
    let mut closed = false;
    for _ in 0..4000 {
        r.data(1, chunk.clone());
        tokio::task::yield_now().await;
        if let Ok(m) = r.rx.try_recv() {
            if matches!(m.payload, Payload::GatewayClose(_)) {
                closed = true;
                break;
            }
        }
        assert!(
            r.session.buffered_bytes() <= 512 * 1024 + 64 * 1024,
            "buffered {}",
            r.session.buffered_bytes()
        );
    }
    assert!(closed, "the connection was never closed at the cap");
    assert_eq!(r.session.buffered_bytes(), 0);
}

#[tokio::test]
async fn the_per_client_cap_is_summed_over_connections() {
    let (port, _held) = mute_service().await;
    let mut r = rig_with(
        GatewayPolicy {
            max_buffered_bytes: 4 * 1024 * 1024,
            max_client_buffered_bytes: 1024 * 1024,
            ..loopback_policy()
        },
        true,
        &[],
    );
    for id in 1..=2 {
        r.open_tcp(id, port);
        r.expect_ok(id).await;
    }
    let chunk = vec![4u8; 64 * 1024];
    let mut closed = false;
    'outer: for _ in 0..3000 {
        for id in 1..=2 {
            r.data(id, chunk.clone());
        }
        tokio::task::yield_now().await;
        while let Ok(m) = r.rx.try_recv() {
            if matches!(m.payload, Payload::GatewayClose(_)) {
                closed = true;
                break 'outer;
            }
        }
    }
    assert!(closed);
}

// ── half-close ────────────────────────────────────────────────────

#[tokio::test]
async fn after_the_clients_close_the_origin_can_still_answer() {
    // An origin that reads to EOF and then replies.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all).await;
                let _ = s.write_all(&[b"got:".as_slice(), &all].concat()).await;
            });
        }
    });
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.data(1, b"request".to_vec());
    r.close(1);
    let msgs = r.drain(800).await;
    let body: Vec<u8> = msgs
        .iter()
        .filter_map(|m| match &m.payload {
            Payload::GatewayData(d) => Some(d.data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(body, b"got:request");
    assert!(
        got_close(&msgs).is_some(),
        "the origin's end is reported too"
    );
}

#[tokio::test]
async fn the_origin_closing_is_reported_once() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let _ = s.write_all(b"bye").await;
        }
    });
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let msgs = r.drain(400).await;
    assert_eq!(data_len(&msgs), 3);
    assert_eq!(
        msgs.iter()
            .filter(|m| matches!(m.payload, Payload::GatewayClose(_)))
            .count(),
        1
    );
}

// ── a half-close does not end the other direction (#271) ──────────

/// An origin that reads to the client's end of file, waits `delay`, and then answers with `reply`.
async fn slow_answer_service(delay: Duration, reply: Vec<u8>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all).await;
                tokio::time::sleep(delay).await;
                let _ = s.write_all(&reply).await;
            });
        }
    });
    port
}

fn policy_with_idle(idle: Option<Duration>) -> GatewayPolicy {
    GatewayPolicy {
        half_close_idle: idle,
        ..loopback_policy()
    }
}

/// Read until the host's GatewayClose, giving credit back as data arrives. Returns the bytes and the close reason.
async fn read_to_close(r: &mut Rig, id: u32) -> (Vec<u8>, Option<String>) {
    let mut body = Vec::new();
    loop {
        match r.next().await.payload {
            Payload::GatewayData(d) => {
                let n = d.data.len() as u32;
                body.extend_from_slice(&d.data);
                r.credit(id, n);
            }
            Payload::GatewayClose(c) => return (body, c.reason),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_answer_sent_two_and_a_half_seconds_after_the_clients_close_arrives_whole() {
    let port = slow_answer_service(Duration::from_millis(2500), b"done\n".to_vec()).await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let t0 = std::time::Instant::now();
    r.close(1);
    let (body, _) = read_to_close(&mut r, 1).await;
    assert_eq!(body, b"done\n");
    assert!(t0.elapsed() >= Duration::from_millis(2400));
}

#[tokio::test]
async fn a_twenty_mib_answer_after_the_close_arrives_whole_and_is_held_back_by_credit() {
    let total = 20 * 1024 * 1024;
    let port = slow_answer_service(Duration::from_millis(0), vec![9u8; total]).await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1);
    // Nobody returns credit for 1.5 s (longer than the old one-second limit): only the window arrives.
    let early = r.drain(1500).await;
    assert!(
        data_len(&early) <= GATEWAY_CREDIT_WINDOW,
        "{} bytes arrived without credit",
        data_len(&early)
    );
    assert!(got_close(&early).is_none());
    // Now read it all.
    let mut got = data_len(&early);
    let mut returned = 0usize;
    r.credit(1, got as u32);
    returned += got;
    while got < total {
        match r.next().await.payload {
            Payload::GatewayData(d) => {
                got += d.data.len();
                r.credit(1, d.data.len() as u32);
                returned += d.data.len();
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, total);
    assert_eq!(returned, total);
}

#[tokio::test]
async fn the_origin_closing_first_does_not_stop_what_the_client_sends_later() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, mut seen) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                // Says goodbye and finishes its own side; it goes on reading.
                let _ = s.write_all(b"bye").await;
                let _ = s.shutdown().await;
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all).await;
                let _ = tx.send(all);
            });
        }
    });
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let early = r.drain(1500).await;
    assert_eq!(data_len(&early), 3);
    assert!(
        got_close(&early).is_some(),
        "the origin's end is a half-close towards the client"
    );
    r.data(1, b"late words".to_vec());
    r.close(1);
    let got = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("the origin saw the client's end of file")
        .unwrap();
    assert_eq!(got, b"late words");
}

#[tokio::test]
async fn both_sides_closing_ends_the_connection_at_once() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all).await; // the client's end of file...
                let _ = s.shutdown().await; // ...and ours at once
            });
        }
    });
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let t0 = std::time::Instant::now();
    r.close(1);
    let (body, _) = read_to_close(&mut r, 1).await;
    assert!(body.is_empty());
    assert!(t0.elapsed() < Duration::from_secs(2));
    // The connection is gone: its id is free again.
    let port = echo_service().await;
    r.open_tcp(1, port);
    r.expect_ok(1).await;
}

#[tokio::test]
async fn a_peer_that_half_closes_and_never_reads_is_ended_by_the_idle_rule_not_sooner() {
    let idle = Duration::from_millis(1500);
    let port = slow_answer_service(Duration::from_millis(0), vec![1u8; 4 * 1024 * 1024]).await;
    let mut r = rig_with(policy_with_idle(Some(idle)), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let t0 = std::time::Instant::now();
    r.close(1);
    // The window's worth arrives, then nothing moves (no credit is returned).
    let early = r.drain(900).await;
    assert!(
        got_close(&early).is_none(),
        "not sooner than the idle bound"
    );
    let mut reason = None;
    while reason.is_none() {
        if let Payload::GatewayClose(c) = r.next().await.payload {
            reason = Some(c.reason);
        }
    }
    assert_eq!(reason.unwrap().as_deref(), Some("idle timeout"));
    assert!(t0.elapsed() >= idle - Duration::from_millis(100));
}

#[tokio::test]
async fn a_half_closed_connection_that_is_quiet_but_alive_is_not_reaped() {
    // Bytes from the origin every 400 ms for 2.4 s with a 1 s bound: each one restarts the clock.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all).await;
                for _ in 0..6 {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    let _ = s.write_all(b"x").await;
                }
            });
        }
    });
    let mut r = rig_with(policy_with_idle(Some(Duration::from_secs(1))), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1);
    let (body, reason) = read_to_close(&mut r, 1).await;
    assert_eq!(body, b"xxxxxx");
    assert_eq!(reason, None, "the origin ended it, not the idle rule");
}

#[tokio::test]
async fn without_an_idle_bound_a_quiet_half_closed_connection_stays() {
    let port = slow_answer_service(Duration::from_secs(3600), b"never".to_vec()).await;
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1);
    let msgs = r.drain(1500).await;
    assert!(got_close(&msgs).is_none());
}

#[tokio::test]
async fn a_client_that_discarded_the_connection_ends_it_at_once_even_with_the_origin_still_writing()
{
    let port = firehose_service().await;
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let _ = r.drain(100).await; // the window's worth arrives, then the origin is held back by credit
    r.send(
        MsgType::GatewayClose,
        Payload::GatewayClose(GatewayClosePayload {
            gateway_id: 1,
            reason: Some(GATEWAY_DISCARDED.into()),
        }),
    );
    let t0 = std::time::Instant::now();
    loop {
        let conns = r.session.inner.conns.lock().unwrap().len();
        if conns == 0 {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(3), "still open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── a destroy after a half-close is told to the peer ──────────────

fn discard(r: &Rig, id: u32) {
    r.send(
        MsgType::GatewayClose,
        Payload::GatewayClose(GatewayClosePayload {
            gateway_id: id,
            reason: Some(GATEWAY_DISCARDED.into()),
        }),
    );
}

async fn conns(r: &Rig) -> usize {
    r.session.inner.conns.lock().unwrap().len()
}

/// Poll until the host holds no connection (a state, not a time).
async fn wait_for_no_connections(r: &Rig) {
    let t0 = std::time::Instant::now();
    while conns(r).await > 0 {
        assert!(t0.elapsed() < Duration::from_secs(5), "still open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_client_that_half_closed_and_then_discards_frees_the_connection_with_the_bound_off() {
    let (port, _held) = mute_service().await;
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1); // the client half-closes; the origin never answers
    let msgs = r.drain(300).await;
    assert!(got_close(&msgs).is_none());
    assert_eq!(
        conns(&r).await,
        1,
        "a half-closed silent connection is held (the bound is off)"
    );
    discard(&r, 1); // its reader is gone
    wait_for_no_connections(&r).await;
    let after = r.drain(200).await;
    assert!(
        got_close(&after).is_none(),
        "it reads nothing more: nothing goes back"
    );
}

#[tokio::test]
async fn a_second_close_without_the_reason_does_not_end_a_half_closed_connection() {
    let (port, _held) = mute_service().await;
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1);
    r.close(1);
    r.send(
        MsgType::GatewayClose,
        Payload::GatewayClose(GatewayClosePayload {
            gateway_id: 1,
            reason: Some("idle timeout".into()),
        }),
    );
    let _ = r.drain(300).await;
    assert_eq!(conns(&r).await, 1);
}

#[tokio::test]
async fn a_second_discard_for_a_connection_that_is_gone_is_ignored() {
    let port = echo_service().await;
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    r.close(1);
    let _ = read_to_close(&mut r, 1).await;
    wait_for_no_connections(&r).await;
    discard(&r, 1);
    discard(&r, 99);
    // The session is untouched: a new connection with that id works.
    r.open_tcp(1, port);
    r.expect_ok(1).await;
}

#[tokio::test]
async fn an_origin_that_half_closed_and_is_then_gone_is_told_to_the_client_once_the_client_writes()
{
    // The origin sends its end of file and goes away. A half-close towards the client already went out; the connection
    // then fails on the next write to the origin, and the client must hear that its direction is over.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let _ = s.shutdown().await;
            drop(s);
        }
    });
    let mut r = rig_with(policy_with_idle(None), true, CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    assert_eq!(
        got_close(&[r.next().await]),
        Some(None),
        "the FIN is a half-close"
    );
    let mut second = None;
    let t0 = std::time::Instant::now();
    while second.is_none() {
        assert!(t0.elapsed() < Duration::from_secs(5), "never told");
        r.data(1, vec![1u8; 16]);
        for m in r.drain(40).await {
            if let Payload::GatewayClose(c) = m.payload {
                second = Some(c.reason);
            }
        }
    }
    assert_eq!(second.unwrap().as_deref(), Some(GATEWAY_DISCARDED));
}

#[tokio::test]
async fn the_idle_bound_on_a_connection_the_origin_half_closed_ends_with_a_discard_for_the_client()
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.shutdown().await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });
    let mut r = rig_with(
        policy_with_idle(Some(Duration::from_millis(300))),
        true,
        CREDIT,
    );
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    assert_eq!(got_close(&[r.next().await]), Some(None));
    match r.next().await.payload {
        Payload::GatewayClose(c) => assert_eq!(c.reason.as_deref(), Some(GATEWAY_DISCARDED)),
        other => panic!("{other:?}"),
    }
    wait_for_no_connections(&r).await;
}

#[tokio::test]
async fn a_host_side_discard_says_so_and_a_half_close_does_not() {
    // The origin resets/vanishes: a plain destroy carries the marker; the origin's FIN does not.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(b"x").await;
                let _ = s.shutdown().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    let mut r = rig(CREDIT);
    r.open_tcp(1, port);
    r.expect_ok(1).await;
    let msgs = r.drain(500).await;
    assert_eq!(
        got_close(&msgs),
        Some(None),
        "a FIN is a half-close: no reason"
    );
}

#[tokio::test]
async fn a_udp_flow_ends_at_the_clients_close() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let mut r = rig(CREDIT);
    r.send(
        MsgType::OpenUdp,
        Payload::OpenUdp(OpenUdpPayload {
            gateway_id: 1,
            host: "127.0.0.1".into(),
            port,
        }),
    );
    r.expect_ok(1).await;
    r.close(1);
    let _ = r.drain(300).await;
    assert!(r.session.inner.conns.lock().unwrap().is_empty());
}

// ── UDP ───────────────────────────────────────────────────────────

#[tokio::test]
async fn udp_datagrams_round_trip() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    let mut r = rig(CREDIT);
    r.send(
        MsgType::OpenUdp,
        Payload::OpenUdp(OpenUdpPayload {
            gateway_id: 1,
            host: "127.0.0.1".into(),
            port,
        }),
    );
    r.expect_ok(1).await;
    r.data(1, b"ping".to_vec());
    match r.next().await.payload {
        Payload::GatewayData(d) => assert_eq!(d.data, b"ping"),
        other => panic!("{other:?}"),
    }
}

// ── UDP as WebTransport datagrams (`gateway-datagram`, #124) ──────────

mod datagrams {
    use super::*;
    use crate::gateway::udp_policy::{Oversize, UdpPolicy};
    use std::sync::atomic::AtomicUsize;
    use wsh_core::gateway_datagram::{decode_datagram, encode_datagram};

    const DG: &[&str] = &[GATEWAY_CREDIT_FEATURE, GATEWAY_DATAGRAM_FEATURE];

    /// A transport's datagrams: what was sent, and a size limit that can be changed.
    struct FakeSink {
        sent: Mutex<Vec<Vec<u8>>>,
        max: AtomicUsize,
    }

    impl FakeSink {
        fn new(max: usize) -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                max: AtomicUsize::new(max),
            })
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl DatagramSink for FakeSink {
        fn send(&self, datagram: Vec<u8>) -> bool {
            self.sent.lock().unwrap().push(datagram);
            true
        }
        fn max_size(&self) -> usize {
            self.max.load(Ordering::Relaxed)
        }
    }

    fn dg_rig(udp: UdpPolicy, features: &[&str], sink: Option<Arc<FakeSink>>) -> Rig {
        let (tx, rx) = mpsc::channel(256);
        let features: Vec<String> = features.iter().map(|f| f.to_string()).collect();
        let policy = GatewayPolicy {
            udp,
            ..loopback_policy()
        };
        let session = GatewaySession::with_datagrams(
            Arc::new(GatewayPolicyEnforcer::new(policy)),
            tx,
            true,
            &features,
            sink.map(|s| s as Arc<dyn DatagramSink>),
        );
        Rig { session, rx }
    }

    /// A UDP origin that records what it gets and echoes it, `times` times over (an amplifier).
    async fn origin(times: usize) -> (u16, mpsc::UnboundedReceiver<Vec<u8>>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 70_000];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let _ = tx.send(buf[..n].to_vec());
                for _ in 0..times {
                    let _ = sock.send_to(&buf[..n], from).await;
                }
            }
        });
        (port, rx)
    }

    async fn open(r: &mut Rig, id: u32, port: u16) {
        r.send(
            MsgType::OpenUdp,
            Payload::OpenUdp(OpenUdpPayload {
                gateway_id: id,
                host: "127.0.0.1".into(),
                port,
            }),
        );
        r.expect_ok(id).await;
    }

    async fn until_sent(sink: &FakeSink, n: usize) {
        for _ in 0..200 {
            if sink.sent().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {n} datagrams, got {}", sink.sent().len());
    }

    #[tokio::test]
    async fn a_flow_on_datagrams_moves_payloads_as_datagrams_and_nothing_as_gatewaydata() {
        let (port, mut seen) = origin(1).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink.clone()));
        assert!(r.session.datagrams_on());
        open(&mut r, 7, port).await;

        r.session.handle_datagram(&encode_datagram(7, b"ping"));
        assert_eq!(seen.recv().await.unwrap(), b"ping", "the origin got it");
        until_sent(&sink, 1).await;
        let (id, payload) = {
            let sent = sink.sent();
            let (id, p) = decode_datagram(&sent[0]).unwrap();
            (id, p.to_vec())
        };
        assert_eq!((id, payload.as_slice()), (7, &b"ping"[..]));
        // The control stream carried nothing else for the flow.
        assert_eq!(data_len(&r.drain(100).await), 0);
    }

    #[tokio::test]
    async fn datagrams_for_unknown_flows_and_malformed_ones_are_dropped() {
        let (port, mut seen) = origin(0).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink.clone()));
        open(&mut r, 1, port).await;
        r.session.handle_datagram(&encode_datagram(2, b"nobody")); // no such flow
        r.session.handle_datagram(&[0, 0, 1]); // shorter than the header
        r.session.handle_datagram(&[]);
        r.session.handle_datagram(&encode_datagram(1, b"real"));
        assert_eq!(
            seen.recv().await.unwrap(),
            b"real",
            "only the real one arrived"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), seen.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_datagram_after_the_flow_closed_is_dropped() {
        let (port, mut seen) = origin(0).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink));
        open(&mut r, 1, port).await;
        r.close(1);
        let _ = r.drain(1300).await; // the flow ends, and the client is told
        r.session.handle_datagram(&encode_datagram(1, b"late"));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), seen.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_client_that_did_not_list_the_feature_is_served_on_the_control_stream_as_before() {
        let (port, mut seen) = origin(1).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), CREDIT, Some(sink.clone()));
        assert!(!r.session.datagrams_on());
        open(&mut r, 1, port).await;
        r.data(1, b"ping".to_vec());
        assert_eq!(seen.recv().await.unwrap(), b"ping");
        match r.next().await.payload {
            Payload::GatewayData(d) => assert_eq!(d.data, b"ping"),
            other => panic!("{other:?}"),
        }
        // A datagram from such a client is not heard, even for a flow it opened.
        r.session.handle_datagram(&encode_datagram(1, b"stray"));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), seen.recv())
                .await
                .is_err()
        );
        assert!(sink.sent().is_empty());
    }

    #[tokio::test]
    async fn udp_datagrams_false_and_a_transport_without_datagrams_keep_every_flow_on_the_control_stream(
    ) {
        for (udp, sink) in [
            (
                UdpPolicy::default().with_datagrams(false, Oversize::Reliable),
                Some(FakeSink::new(1200)),
            ),
            (UdpPolicy::default(), None),
        ] {
            let (port, mut seen) = origin(1).await;
            let mut r = dg_rig(udp, DG, sink.clone());
            assert!(!r.session.datagrams_on());
            open(&mut r, 1, port).await;
            r.data(1, b"ping".to_vec());
            assert_eq!(seen.recv().await.unwrap(), b"ping");
            assert!(matches!(r.next().await.payload, Payload::GatewayData(_)));
            if let Some(s) = sink {
                assert!(s.sent().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn a_reply_over_the_datagram_limit_goes_on_the_control_stream_by_default() {
        let (port, mut seen) = origin(1).await;
        // 1200 bytes fit; a 1197-byte payload is the largest that does (limit minus the 4-byte id)
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink.clone()));
        open(&mut r, 1, port).await;

        r.session
            .handle_datagram(&encode_datagram(1, &vec![5u8; 1196]));
        assert_eq!(seen.recv().await.unwrap().len(), 1196);
        until_sent(&sink, 1).await;
        assert_eq!(
            sink.sent()[0].len(),
            1200,
            "exactly at the limit: a datagram"
        );

        r.session
            .handle_datagram(&encode_datagram(1, &vec![6u8; 1197]));
        assert_eq!(seen.recv().await.unwrap().len(), 1197);
        match r.next().await.payload {
            Payload::GatewayData(d) => {
                assert_eq!(d.data.len(), 1197, "one over: the control stream")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(sink.sent().len(), 1, "and not also as a datagram");
    }

    #[tokio::test]
    async fn udp_oversize_drop_drops_a_reply_that_does_not_fit() {
        let (port, mut seen) = origin(1).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(
            UdpPolicy::default().with_datagrams(true, Oversize::Drop),
            DG,
            Some(sink.clone()),
        );
        open(&mut r, 1, port).await;
        r.session
            .handle_datagram(&encode_datagram(1, &vec![6u8; 1197]));
        assert_eq!(seen.recv().await.unwrap().len(), 1197);
        assert_eq!(data_len(&r.drain(200).await), 0);
        assert!(sink.sent().is_empty());
    }

    #[tokio::test]
    async fn the_limit_is_read_again_for_every_payload() {
        let (port, mut seen) = origin(1).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink.clone()));
        open(&mut r, 1, port).await;
        r.session.handle_datagram(&encode_datagram(1, &[1u8; 500]));
        seen.recv().await.unwrap();
        until_sent(&sink, 1).await;
        sink.max.store(300, Ordering::Relaxed); // the path MTU estimate fell
        r.session.handle_datagram(&encode_datagram(1, &[2u8; 500]));
        seen.recv().await.unwrap();
        assert!(matches!(r.next().await.payload, Payload::GatewayData(_)));
        sink.max.store(0, Ordering::Relaxed); // datagrams no longer taken at all
        r.session.handle_datagram(&encode_datagram(1, &[3u8; 10]));
        seen.recv().await.unwrap();
        assert!(matches!(r.next().await.payload, Payload::GatewayData(_)));
        assert_eq!(sink.sent().len(), 1);
    }

    #[tokio::test]
    async fn the_oversize_payload_from_the_client_on_the_control_stream_still_reaches_the_origin() {
        let (port, mut seen) = origin(0).await;
        let sink = FakeSink::new(1200);
        let mut r = dg_rig(UdpPolicy::default(), DG, Some(sink));
        open(&mut r, 1, port).await;
        r.data(1, vec![8u8; 5000]);
        assert_eq!(seen.recv().await.unwrap().len(), 5000);
    }

    /// What a token bucket guarantees whatever the scheduling: no more than `burst + rate * T` over `T` seconds.
    #[tokio::test]
    async fn the_bounds_apply_to_the_datagram_path_per_flow_per_client_and_in_bytes() {
        // per flow: 20/s, burst 16; 200 datagrams in a burst
        let (port, mut seen) = origin(0).await;
        let sink = FakeSink::new(1200);
        let started = std::time::Instant::now();
        let mut r = dg_rig(UdpPolicy::new(16, 20, 0, 0, 60).unwrap(), DG, Some(sink));
        open(&mut r, 1, port).await;
        for _ in 0..200 {
            r.session.handle_datagram(&encode_datagram(1, &[1u8; 50]));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut got = 0;
        while seen.try_recv().is_ok() {
            got += 1;
        }
        let most = 16.0 + 20.0 * started.elapsed().as_secs_f64();
        assert!(
            got >= 1 && (got as f64) <= most + 1.0,
            "{got} of 200, at most {most}"
        );

        // per client, over two flows: 20/s, burst 32
        let (port, mut seen) = origin(0).await;
        let started = std::time::Instant::now();
        let mut r = dg_rig(
            UdpPolicy::new(16, 0, 20, 0, 60).unwrap(),
            DG,
            Some(FakeSink::new(1200)),
        );
        open(&mut r, 1, port).await;
        open(&mut r, 2, port).await;
        for i in 0..200u32 {
            r.session
                .handle_datagram(&encode_datagram(1 + i % 2, &[1u8; 50]));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut got = 0;
        while seen.try_recv().is_ok() {
            got += 1;
        }
        let most = 32.0 + 20.0 * started.elapsed().as_secs_f64();
        assert!(
            got >= 1 && (got as f64) <= most + 1.0,
            "{got} of 200, at most {most}"
        );

        // bytes per client, the amplification bound: small queries, 8000-byte answers, 4 answers each
        let (port, mut seen) = origin(4).await;
        let sink = FakeSink::new(10_000);
        let started = std::time::Instant::now();
        let mut r = dg_rig(
            UdpPolicy::new(16, 0, 0, 40_000, 60).unwrap(),
            DG,
            Some(sink.clone()),
        );
        open(&mut r, 1, port).await;
        // One query first, while the burst is full: its answers (4 x 8000) pass, so the bound is seen to let traffic through.
        r.session.handle_datagram(&encode_datagram(1, &[7u8; 8000]));
        until_sent(&sink, 1).await;
        for _ in 0..39 {
            r.session.handle_datagram(&encode_datagram(1, &[7u8; 8000]));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        while seen.try_recv().is_ok() {}
        let bytes: usize = sink.sent().iter().map(|d| d.len() - 4).sum();
        // The burst is max(40000 / 4, 65536) bytes, refilled at 40000 a second, shared by the queries and the answers: of
        // the 320000 query bytes and 1280000 answer bytes offered, no more than burst + rate * T pass in total.
        let most = 65_536.0 + 40_000.0 * started.elapsed().as_secs_f64();
        assert!(
            bytes >= 8000 && (bytes as f64) <= most,
            "{bytes} bytes, at most {most}"
        );
    }

    #[tokio::test]
    async fn a_flow_with_traffic_only_as_datagrams_from_the_client_is_not_idle() {
        // udp_idle_secs = 1; datagrams in one direction only for about 2.4 s keep the flow open.
        let (port, _seen) = origin(0).await;
        let mut r = dg_rig(
            UdpPolicy::new(16, 0, 0, 0, 1).unwrap(),
            DG,
            Some(FakeSink::new(1200)),
        );
        open(&mut r, 1, port).await;
        for _ in 0..8 {
            r.session.handle_datagram(&encode_datagram(1, &[1u8; 10]));
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let msgs = r.drain(10).await;
        assert!(got_close(&msgs).is_none(), "kept alive by datagrams");
        // and it closes once they stop
        let msgs = r.drain(2500).await;
        assert!(got_close(&msgs).is_some(), "idle at last");
    }
}

// ── unix sockets ──────────────────────────────────────────────────

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tokio::net::{UnixListener, UnixStream};

    /// A scratch directory (resolved, so it matches what realpath says) that removes itself.
    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "wgw-{}-{}",
                std::process::id(),
                rand::random::<u16>()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(std::fs::canonicalize(p).unwrap())
        }
        fn join(&self, n: &str) -> String {
            self.0.join(n).to_string_lossy().into_owned()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn unix_rig(
        connect: Vec<String>,
        listen: Vec<String>,
        replace: bool,
        features: &[&str],
    ) -> Rig {
        rig_with(
            GatewayPolicy {
                unix: UnixPolicy::new(connect, listen, replace, 4).unwrap(),
                ..GatewayPolicy::default()
            },
            true,
            features,
        )
    }

    fn open_unix(r: &Rig, id: u32, path: &str) {
        r.send(
            MsgType::OpenUnix,
            Payload::OpenUnix(OpenUnixPayload {
                gateway_id: id,
                path: path.into(),
            }),
        );
    }

    fn listen_unix(r: &Rig, id: u32, path: &str, replace: Option<bool>) {
        r.send(
            MsgType::ListenUnix,
            Payload::ListenUnix(ListenUnixPayload {
                listener_id: id,
                path: path.into(),
                replace,
            }),
        );
    }

    async fn expect_listen_ok(r: &mut Rig, id: u32) {
        match r.next().await.payload {
            Payload::ListenOk(ok) => assert_eq!((ok.listener_id, ok.actual_port), (id, 0)),
            other => panic!("expected ListenOk, got {other:?}"),
        }
    }

    async fn expect_listen_fail(r: &mut Rig, id: u32) -> String {
        match r.next().await.payload {
            Payload::ListenFail(f) => {
                assert_eq!(f.listener_id, id);
                f.reason
            }
            other => panic!("expected ListenFail, got {other:?}"),
        }
    }

    fn echo_unix(path: &str) {
        let l = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    #[tokio::test]
    async fn unix_sockets_are_refused_by_default_and_by_an_empty_policy() {
        let d = Dir::new();
        echo_unix(&d.join("e.sock"));
        for mut r in [rig(CREDIT), unix_rig(vec![], vec![], false, CREDIT)] {
            open_unix(&r, 1, &d.join("e.sock"));
            let (code, _) = r.expect_fail(1).await;
            assert_eq!(code, 4);
            listen_unix(&r, 2, &d.join("l.sock"), None);
            expect_listen_fail(&mut r, 2).await;
        }
    }

    #[tokio::test]
    async fn an_allowed_socket_is_reachable_and_nothing_else_is() {
        let d = Dir::new();
        echo_unix(&d.join("e.sock"));
        echo_unix(&d.join("other.sock"));
        let mut r = unix_rig(vec![d.join("e.sock")], vec![], false, CREDIT);
        open_unix(&r, 1, &d.join("e.sock"));
        r.expect_ok(1).await;
        r.data(1, b"over unix".to_vec());
        match r.next().await.payload {
            Payload::GatewayData(m) => assert_eq!(m.data, b"over unix"),
            other => panic!("{other:?}"),
        }
        open_unix(&r, 2, &d.join("other.sock"));
        assert_eq!(r.expect_fail(2).await.0, 4);
        // Missing: refused as a refusal to connect, not as a policy decision about a path that exists.
        open_unix(&r, 3, &d.join("e.sock").replace("e.sock", "gone.sock"));
        assert_eq!(r.expect_fail(3).await.0, 4);
    }

    #[tokio::test]
    async fn a_directory_prefix_allows_what_is_in_it() {
        let d = Dir::new();
        echo_unix(&d.join("a.sock"));
        let mut r = unix_rig(vec![format!("{}/", d.0.display())], vec![], false, CREDIT);
        open_unix(&r, 1, &d.join("a.sock"));
        r.expect_ok(1).await;
    }

    #[tokio::test]
    async fn the_target_must_be_a_socket() {
        let d = Dir::new();
        std::fs::write(d.join("plain"), b"x").unwrap();
        let mut r = unix_rig(vec![format!("{}/", d.0.display())], vec![], false, CREDIT);
        open_unix(&r, 1, &d.join("plain"));
        let (code, msg) = r.expect_fail(1).await;
        assert_eq!((code, msg.as_str()), (4, "not a socket"));
    }

    #[tokio::test]
    async fn a_symlink_cannot_lead_out_of_the_allowed_place() {
        let allowed = Dir::new();
        let outside = Dir::new();
        echo_unix(&outside.join("secret.sock"));
        symlink(&outside.0, allowed.join("dir")).unwrap();
        symlink(outside.join("secret.sock"), allowed.join("file.sock")).unwrap();
        let mut r = unix_rig(
            vec![format!("{}/", allowed.0.display())],
            vec![],
            false,
            CREDIT,
        );
        // Through a symlinked directory: the parent resolves outside the prefix.
        open_unix(&r, 1, &allowed.join("dir/secret.sock"));
        assert_eq!(r.expect_fail(1).await.0, 4);
        // A symlinked socket inside the prefix: lstat says it is not a socket.
        open_unix(&r, 2, &allowed.join("file.sock"));
        let (code, msg) = r.expect_fail(2).await;
        assert_eq!((code, msg.as_str()), (4, "not a socket"));
        // `..` is refused outright.
        open_unix(&r, 3, &allowed.join("x/../dir/secret.sock"));
        assert_eq!(r.expect_fail(3).await.0, 4);
    }

    #[tokio::test]
    async fn the_abstract_namespace_is_refused_unless_listed() {
        let mut r = unix_rig(vec!["/nonexistent-dir/".into()], vec![], false, CREDIT);
        open_unix(&r, 1, "@wsh-test-abstract");
        assert_eq!(r.expect_fail(1).await.0, 4);
    }

    #[tokio::test]
    async fn unix_connections_count_against_the_connection_limit() {
        let d = Dir::new();
        echo_unix(&d.join("e.sock"));
        let mut r = rig_with(
            GatewayPolicy {
                max_connections: 1,
                unix: UnixPolicy::new(vec![d.join("e.sock")], vec![], false, 4).unwrap(),
                ..GatewayPolicy::default()
            },
            true,
            CREDIT,
        );
        open_unix(&r, 1, &d.join("e.sock"));
        r.expect_ok(1).await;
        open_unix(&r, 2, &d.join("e.sock"));
        assert_eq!(r.expect_fail(2).await.0, 7);
    }

    #[tokio::test]
    async fn listening_creates_a_private_socket_hands_connections_over_and_cleans_up() {
        let d = Dir::new();
        let path = d.join("l.sock");
        let mut r = unix_rig(vec![], vec![path.clone()], false, CREDIT);
        listen_unix(&r, 1, &path, None);
        expect_listen_ok(&mut r, 1).await;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a created socket is private");

        let mut peer = UnixStream::connect(&path).await.unwrap();
        let (listener_id, channel_id) = match r.next().await.payload {
            Payload::InboundOpen(o) => {
                assert_eq!(o.peer_port, 0);
                (o.listener_id, o.channel_id)
            }
            other => panic!("expected InboundOpen, got {other:?}"),
        };
        assert_eq!(listener_id, 1);
        r.send(
            MsgType::InboundAccept,
            Payload::InboundAccept(InboundAcceptPayload {
                channel_id,
                gateway_id: Some(77),
            }),
        );
        peer.write_all(b"from the socket").await.unwrap();
        match r.next().await.payload {
            Payload::GatewayData(m) => {
                assert_eq!((m.gateway_id, m.data), (77, b"from the socket".to_vec()))
            }
            other => panic!("{other:?}"),
        }
        r.data(77, b"to the socket".to_vec());
        let mut buf = [0u8; 13];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"to the socket");

        // ListenClose removes the socket file.
        r.send(
            MsgType::ListenClose,
            Payload::ListenClose(ListenClosePayload { listener_id: 1 }),
        );
        let _ = r.drain(300).await;
        assert!(
            !std::path::Path::new(&path).exists(),
            "the socket is unlinked on close"
        );
    }

    #[tokio::test]
    async fn dropping_the_connection_unlinks_its_sockets() {
        let d = Dir::new();
        let path = d.join("l.sock");
        let mut r = unix_rig(vec![], vec![path.clone()], false, CREDIT);
        listen_unix(&r, 1, &path, None);
        expect_listen_ok(&mut r, 1).await;
        assert!(std::path::Path::new(&path).exists());
        drop(r);
        assert!(!std::path::Path::new(&path).exists());
    }

    #[tokio::test]
    async fn a_listen_path_outside_the_listen_list_is_refused() {
        let d = Dir::new();
        let mut r = unix_rig(
            vec![format!("{}/", d.0.display())],
            vec![d.join("ok.sock")],
            false,
            CREDIT,
        );
        // `connect` entries do not grant `listen`.
        listen_unix(&r, 1, &d.join("nope.sock"), None);
        expect_listen_fail(&mut r, 1).await;
        assert!(!std::path::Path::new(&d.join("nope.sock")).exists());
    }

    #[tokio::test]
    async fn an_existing_socket_file_is_replaced_only_when_asked_and_allowed_and_stale() {
        let d = Dir::new();
        let path = d.join("s.sock");
        // A stale socket file: bound, then the listener dropped without unlinking.
        std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(std::path::Path::new(&path).exists());

        // Policy forbids replacing: refused even when asked.
        let mut r = unix_rig(vec![], vec![path.clone()], false, CREDIT);
        listen_unix(&r, 1, &path, Some(true));
        assert!(expect_listen_fail(&mut r, 1).await.contains("not allowed"));
        // Policy allows, the client did not ask: refused.
        let mut r = unix_rig(vec![], vec![path.clone()], true, CREDIT);
        listen_unix(&r, 1, &path, None);
        assert!(expect_listen_fail(&mut r, 1)
            .await
            .contains("address in use"));
        listen_unix(&r, 2, &path, Some(false));
        assert!(expect_listen_fail(&mut r, 2)
            .await
            .contains("address in use"));
        // Both: replaced.
        listen_unix(&r, 3, &path, Some(true));
        expect_listen_ok(&mut r, 3).await;
        drop(r);
    }

    #[tokio::test]
    async fn a_live_socket_is_never_replaced_and_neither_is_a_plain_file() {
        let d = Dir::new();
        let live = d.join("live.sock");
        echo_unix(&live);
        let mut r = unix_rig(vec![], vec![format!("{}/", d.0.display())], true, CREDIT);
        listen_unix(&r, 1, &live, Some(true));
        assert!(expect_listen_fail(&mut r, 1).await.contains("live"));
        assert!(
            UnixStream::connect(&live).await.is_ok(),
            "the live socket is untouched"
        );

        std::fs::write(d.join("file"), b"data").unwrap();
        listen_unix(&r, 2, &d.join("file"), Some(true));
        assert!(expect_listen_fail(&mut r, 2).await.contains("not a socket"));
        assert_eq!(std::fs::read(d.join("file")).unwrap(), b"data");
    }

    #[tokio::test]
    async fn the_number_of_unix_listeners_is_capped() {
        let d = Dir::new();
        let mut r = rig_with(
            GatewayPolicy {
                unix: UnixPolicy::new(vec![], vec![format!("{}/", d.0.display())], false, 1)
                    .unwrap(),
                ..GatewayPolicy::default()
            },
            true,
            CREDIT,
        );
        listen_unix(&r, 1, &d.join("a.sock"), None);
        expect_listen_ok(&mut r, 1).await;
        listen_unix(&r, 2, &d.join("b.sock"), None);
        assert!(expect_listen_fail(&mut r, 2).await.contains("too many"));
        listen_unix(&r, 1, &d.join("c.sock"), None);
        assert!(expect_listen_fail(&mut r, 1).await.contains("in use"));
    }

    #[tokio::test]
    async fn too_many_unanswered_inbound_connections_are_dropped() {
        let d = Dir::new();
        let path = d.join("l.sock");
        let mut r = unix_rig(vec![], vec![path.clone()], false, CREDIT);
        listen_unix(&r, 1, &path, None);
        expect_listen_ok(&mut r, 1).await;
        let mut peers = Vec::new();
        for _ in 0..(MAX_PENDING_INBOUND + 8) {
            peers.push(UnixStream::connect(&path).await.unwrap());
        }
        let opens = r
            .drain(500)
            .await
            .iter()
            .filter(|m| matches!(m.payload, Payload::InboundOpen(_)))
            .count();
        assert_eq!(opens, MAX_PENDING_INBOUND);
    }
}

// ── reverse TCP listeners ─────────────────────────────────────────

async fn listen_tcp(r: &mut Rig, id: u32, requested_bind: &str) -> Envelope {
    r.send(
        MsgType::ListenRequest,
        Payload::ListenRequest(ListenRequestPayload {
            listener_id: id,
            port: 0,
            bind_addr: requested_bind.into(),
        }),
    );
    r.next().await
}

fn reverse_policy(bind: std::net::IpAddr) -> GatewayPolicy {
    GatewayPolicy {
        allowed_destinations: vec!["*".into()],
        enable_reverse_tunnels: true,
        reverse_bind_addr: bind,
        ..GatewayPolicy::default()
    }
}

#[tokio::test]
async fn a_tcp_listener_is_refused_unless_reverse_tunnels_are_enabled() {
    let mut r = rig_with(
        GatewayPolicy {
            enable_reverse_tunnels: false,
            ..loopback_policy()
        },
        true,
        CREDIT,
    );
    let reply = listen_tcp(&mut r, 1, "127.0.0.1").await;
    assert!(matches!(reply.payload, Payload::ListenFail(_)), "{reply:?}");
}

#[tokio::test]
async fn a_tcp_listener_binds_where_the_config_says_not_where_the_client_asks() {
    let lo = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    for requested in ["0.0.0.0", "::", "192.168.1.5", "not an address", ""] {
        let mut r = rig_with(reverse_policy(lo), true, CREDIT);
        let reply = listen_tcp(&mut r, 1, requested).await;
        let port = match reply.payload {
            Payload::ListenOk(ok) => ok.actual_port,
            other => panic!("{requested}: {other:?}"),
        };
        assert!(
            TcpStream::connect(("127.0.0.1", port)).await.is_ok(),
            "{requested}"
        );
    }
}

#[tokio::test]
async fn a_tcp_listener_hands_inbound_connections_to_the_client_and_relays_them() {
    let lo = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let mut r = rig_with(reverse_policy(lo), true, CREDIT);
    let port = match listen_tcp(&mut r, 5, "0.0.0.0").await.payload {
        Payload::ListenOk(ok) => ok.actual_port,
        other => panic!("{other:?}"),
    };
    let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let channel_id = match r.next().await.payload {
        Payload::InboundOpen(o) => {
            assert_eq!(o.peer_addr, "127.0.0.1");
            o.channel_id
        }
        other => panic!("{other:?}"),
    };
    r.send(
        MsgType::InboundAccept,
        Payload::InboundAccept(InboundAcceptPayload {
            channel_id,
            gateway_id: Some(9),
        }),
    );
    peer.write_all(b"in").await.unwrap();
    match r.next().await.payload {
        Payload::GatewayData(d) => assert_eq!((d.gateway_id, d.data), (9, b"in".to_vec())),
        other => panic!("{other:?}"),
    }
    // Rejecting drops the next one.
    let mut peer2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let ch2 = match r.next().await.payload {
        Payload::InboundOpen(o) => o.channel_id,
        other => panic!("{other:?}"),
    };
    r.send(
        MsgType::InboundReject,
        Payload::InboundReject(InboundRejectPayload {
            channel_id: ch2,
            reason: None,
        }),
    );
    let mut buf = [0u8; 1];
    assert_eq!(
        peer2.read(&mut buf).await.unwrap_or(0),
        0,
        "a rejected connection is closed"
    );
}
