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
