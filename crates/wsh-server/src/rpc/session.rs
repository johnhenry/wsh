//! Per-connection glue: binds `rpc` channels to client-opened QMux streams.
//!
//! The flow mirrors an exec channel on the JS server. `Open { kind: "rpc" }` is
//! answered `OpenOk` (`data_mode: stream`); the client then opens one QMux
//! stream per channel, and streams bind to channels in `OpenOk` order. The
//! stream carries a CBOR sequence of JSON-RPC messages (see [`super::channel`]).

use super::channel::{self, ChannelConfig, Ended, Input};
use super::protocols::{HostInfo, Protocol};
use super::{valid_protocol_name, RpcSettings, WSH_FS, WSH_HOST};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use wsh_core::messages::{
    ClosePayload, Envelope, ExitPayload, MsgType, OpenFailPayload, OpenOkPayload, Payload,
    SessionDataMode,
};
use wsh_core::qmux_connection::QMuxConnection;

/// Channels per connection (the JS server's `MAX_CHANNELS`).
const MAX_RPC_CHANNELS: usize = 64;

/// The wire type code of `Open`.
const OPEN_TYPE: i128 = 0x10;

/// If `raw` (one control-stream CBOR payload) is an `Open` with `kind: "rpc"`,
/// return its protocol name (`command`, possibly empty).
///
/// `rpc` is not in the generated `ChannelKind` enum (the kind is a free string
/// on the wire and the spec does not list it), so the typed decoder would
/// reject the message. This looks at the raw map instead, leaving the spec and
/// codegen untouched.
pub fn peek_rpc_open(raw: &[u8]) -> Option<String> {
    let v: ciborium::value::Value = ciborium::from_reader(raw).ok()?;
    let ty = match super::get(&v, "type")? {
        ciborium::value::Value::Integer(i) => i128::from(*i),
        _ => return None,
    };
    if ty != OPEN_TYPE {
        return None;
    }
    match super::get(&v, "kind")? {
        ciborium::value::Value::Text(k) if k == "rpc" => {}
        _ => return None,
    }
    Some(match super::get(&v, "command") {
        Some(ciborium::value::Value::Text(c)) => c.clone(),
        _ => String::new(),
    })
}

pub fn open_fail(reason: impl Into<String>) -> Envelope {
    Envelope {
        msg_type: MsgType::OpenFail,
        payload: Payload::OpenFail(OpenFailPayload {
            reason: reason.into(),
        }),
    }
}

fn open_ok(channel_id: u32) -> Envelope {
    Envelope {
        msg_type: MsgType::OpenOk,
        payload: Payload::OpenOk(OpenOkPayload {
            channel_id,
            stream_ids: vec![],
            data_mode: SessionDataMode::Stream,
            capabilities: vec![],
            session_id: None,
            token: None,
        }),
    }
}

struct Pending {
    channel_id: u32,
    protocol: Protocol,
    /// The client closed the channel before its stream arrived: that stream is closed unbound.
    cancelled: bool,
}

/// What the connection knows about an open channel.
enum Channel {
    Pending,
    Bound(mpsc::UnboundedSender<Input>),
}

/// All rpc channels of one connection.
pub struct RpcSessions {
    settings: Option<Arc<RpcSettings>>,
    /// `ServerHello.features`, reported by `host.info`.
    features: Vec<String>,
    username: String,
    pending: VecDeque<Pending>,
    channels: HashMap<u32, Channel>,
    streams: HashMap<u64, u32>,
    live: Arc<AtomicUsize>,
}

impl RpcSessions {
    pub fn new(settings: Option<Arc<RpcSettings>>, features: Vec<String>) -> Self {
        Self {
            settings,
            features,
            username: String::new(),
            pending: VecDeque::new(),
            channels: HashMap::new(),
            streams: HashMap::new(),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Record who authenticated (reported by `host.info`).
    pub fn set_user(&mut self, user: &str) {
        self.username = user.to_string();
    }

    /// Whether a (possibly former) rpc channel has this id.
    pub fn owns_channel(&self, channel_id: u32) -> bool {
        self.channels.contains_key(&channel_id)
    }

    /// Whether this QMux stream is bound to an rpc channel.
    pub fn owns_stream(&self, stream_id: u64) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// Handle `Open { kind: "rpc", command: protocol }`: `OpenOk` (the channel's stream follows) or `OpenFail`.
    ///
    /// `channel_id` is only consumed on success; `needs_files` is whether the
    /// key may use file access (`wsh-fs`).
    pub fn open(
        &mut self,
        protocol: &str,
        mut alloc_channel_id: impl FnMut() -> u32,
        allow_fs: bool,
    ) -> Envelope {
        let Some(settings) = self.settings.clone() else {
            return open_fail("UNSUPPORTED_PROTOCOL: rpc is not enabled on this server");
        };
        if self.live.load(Ordering::Relaxed) >= MAX_RPC_CHANNELS {
            return open_fail("too many open channels");
        }
        let handler = if !valid_protocol_name(protocol) {
            None
        } else if protocol == WSH_HOST {
            Some(Protocol::Host(Arc::new(HostInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                features: self.features.clone(),
                user: self.username.clone(),
                protocols: settings.protocols().iter().map(|s| s.to_string()).collect(),
                max_message_bytes: settings.max_message_bytes,
            })))
        } else if protocol == WSH_FS {
            match &settings.fs {
                Some(fs) if allow_fs => Some(Protocol::Fs(fs.clone())),
                Some(_) => return open_fail("file transfer not permitted for this key"),
                None => None,
            }
        } else {
            None
        };
        let Some(handler) = handler else {
            return open_fail(format!(
                "UNSUPPORTED_PROTOCOL: protocol \"{protocol}\" is not supported by this server"
            ));
        };
        let channel_id = alloc_channel_id();
        self.live.fetch_add(1, Ordering::Relaxed);
        self.channels.insert(channel_id, Channel::Pending);
        self.pending.push_back(Pending {
            channel_id,
            protocol: handler,
            cancelled: false,
        });
        debug!(channel_id, protocol, "rpc channel opened");
        open_ok(channel_id)
    }

    /// A client-opened QMux stream appeared: bind it to the oldest unbound channel.
    /// Returns false if there was none (the caller closes the stream).
    pub fn on_stream_open(
        &mut self,
        stream_id: u64,
        qmux: &Arc<QMuxConnection>,
        control: mpsc::Sender<Envelope>,
    ) -> bool {
        let Some(settings) = self.settings.clone() else {
            return false;
        };
        let Some(p) = self.pending.pop_front() else {
            return false;
        };
        if p.cancelled {
            self.live.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        let channel_id = p.channel_id;
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(32);
        self.channels.insert(channel_id, Channel::Bound(in_tx));
        self.streams.insert(stream_id, channel_id);

        let writer_qmux = qmux.clone();
        let writer = tokio::spawn(async move {
            while let Some(bytes) = out_rx.recv().await {
                if writer_qmux.write_stream(stream_id, &bytes).await.is_err() {
                    break;
                }
            }
        });
        let cfg = ChannelConfig {
            max_message_bytes: settings.max_message_bytes,
            max_inflight: settings.max_inflight,
        };
        let qmux = qmux.clone();
        let live = self.live.clone();
        tokio::spawn(async move {
            let ended = channel::run(cfg, Arc::new(p.protocol), in_rx, out_tx).await;
            // Let what was queued reach the wire (bounded: the peer may be gone).
            let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
            match &ended {
                Ended::HostClosed(why) => {
                    debug!(channel_id, why = %why, "rpc channel closed by host")
                }
                other => debug!(channel_id, ?other, "rpc channel ended"),
            }
            match ended {
                Ended::HostClosed(_) | Ended::StreamEnd => {
                    // Close our end of the stream, then tell the client the channel is over.
                    let _ = qmux.close_stream(stream_id);
                    let _ = control
                        .send(Envelope {
                            msg_type: MsgType::Exit,
                            payload: Payload::Exit(ExitPayload {
                                channel_id,
                                code: 0,
                            }),
                        })
                        .await;
                    let _ = control
                        .send(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        })
                        .await;
                }
                Ended::PeerKilled => {
                    let _ = qmux.close_stream(stream_id);
                }
                Ended::StreamReset | Ended::Dropped => {}
            }
            live.fetch_sub(1, Ordering::Relaxed);
        });
        true
    }

    fn input(&self, stream_id: u64) -> Option<&mpsc::UnboundedSender<Input>> {
        match self.channels.get(self.streams.get(&stream_id)?) {
            Some(Channel::Bound(tx)) => Some(tx),
            _ => None,
        }
    }

    /// Bytes arrived on a bound stream. Returns false if the stream is not an rpc stream.
    pub fn on_stream_data(&self, stream_id: u64, data: Vec<u8>) -> bool {
        match self.input(stream_id) {
            Some(tx) => {
                let _ = tx.send(Input::Data(data));
                true
            }
            None => false,
        }
    }

    pub fn on_stream_end(&self, stream_id: u64) -> bool {
        match self.input(stream_id) {
            Some(tx) => {
                let _ = tx.send(Input::End);
                true
            }
            None => false,
        }
    }

    pub fn on_stream_reset(&self, stream_id: u64) -> bool {
        match self.input(stream_id) {
            Some(tx) => {
                let _ = tx.send(Input::Reset);
                true
            }
            None => false,
        }
    }

    /// The client sent `Close` for a channel. Returns true if it was an rpc channel
    /// (the caller must not treat it as a session `Close`).
    pub fn on_close(&mut self, channel_id: u32) -> bool {
        match self.channels.remove(&channel_id) {
            None => false,
            Some(Channel::Bound(tx)) => {
                let _ = tx.send(Input::Kill);
                self.streams.retain(|_, c| *c != channel_id);
                true
            }
            Some(Channel::Pending) => {
                if let Some(p) = self.pending.iter_mut().find(|p| p.channel_id == channel_id) {
                    p.cancelled = true;
                } else {
                    warn!(channel_id, "pending rpc channel without a queue entry");
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn enc(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    fn open_msg(kind: &str, command: Option<&str>) -> Vec<u8> {
        let mut m = vec![
            (super::super::text("type"), super::super::int(0x10)),
            (super::super::text("kind"), super::super::text(kind)),
        ];
        if let Some(c) = command {
            m.push((super::super::text("command"), super::super::text(c)));
        }
        enc(&Value::Map(m))
    }

    #[test]
    fn peeks_rpc_opens_only() {
        assert_eq!(
            peek_rpc_open(&open_msg("rpc", Some("wsh-host"))),
            Some("wsh-host".into())
        );
        assert_eq!(peek_rpc_open(&open_msg("rpc", None)), Some(String::new()));
        assert_eq!(peek_rpc_open(&open_msg("exec", Some("ls"))), None);
        assert_eq!(peek_rpc_open(&[0xff, 0x00]), None);
        // not an Open
        let close = enc(&Value::Map(vec![
            (super::super::text("type"), super::super::int(0x16)),
            (super::super::text("kind"), super::super::text("rpc")),
        ]));
        assert_eq!(peek_rpc_open(&close), None);
    }

    fn settings(fs: bool) -> Arc<RpcSettings> {
        Arc::new(RpcSettings {
            max_message_bytes: 4096,
            max_inflight: 8,
            fs: fs.then(|| {
                super::super::fs::FileAccess::new(std::path::Path::new("/tmp"), false, 1024)
                    .unwrap()
            }),
        })
    }

    fn reason(e: &Envelope) -> String {
        match &e.payload {
            Payload::OpenFail(p) => p.reason.clone(),
            other => panic!("expected OpenFail, got {other:?}"),
        }
    }

    #[test]
    fn open_negotiates_protocols() {
        let mut s = RpcSessions::new(Some(settings(false)), vec!["rpc".into()]);
        let mut next = 10;
        let mut alloc = || {
            next += 1;
            next
        };
        let ok = s.open("wsh-host", &mut alloc, true);
        assert!(
            matches!(&ok.payload, Payload::OpenOk(p) if p.channel_id == 11 && p.data_mode == SessionDataMode::Stream)
        );
        // wsh-fs is not configured
        assert!(reason(&s.open("wsh-fs", &mut alloc, true))
            .starts_with("UNSUPPORTED_PROTOCOL: protocol \"wsh-fs\""));
        // unknown / malformed names
        assert!(reason(&s.open("mcp", &mut alloc, true)).contains("not supported"));
        assert!(reason(&s.open("", &mut alloc, true)).contains("not supported"));
        assert!(reason(&s.open("bad name", &mut alloc, true)).contains("not supported"));
        // a failed open consumed no channel id
        assert!(
            matches!(&s.open("wsh-host", &mut alloc, true).payload, Payload::OpenOk(p) if p.channel_id == 12)
        );
    }

    #[test]
    fn disabled_rpc_and_unpermitted_fs_are_refused() {
        let mut off = RpcSessions::new(None, vec![]);
        assert_eq!(
            reason(&off.open("wsh-host", || 1, true)),
            "UNSUPPORTED_PROTOCOL: rpc is not enabled on this server"
        );
        let mut s = RpcSessions::new(Some(settings(true)), vec![]);
        assert_eq!(
            reason(&s.open("wsh-fs", || 1, false)),
            "file transfer not permitted for this key"
        );
        assert!(matches!(
            s.open("wsh-fs", || 2, true).payload,
            Payload::OpenOk(_)
        ));
    }

    #[test]
    fn channel_cap_applies() {
        let mut s = RpcSessions::new(Some(settings(false)), vec![]);
        let mut n = 0;
        for _ in 0..MAX_RPC_CHANNELS {
            assert!(matches!(
                s.open(
                    "wsh-host",
                    || {
                        n += 1;
                        n
                    },
                    true
                )
                .payload,
                Payload::OpenOk(_)
            ));
        }
        assert_eq!(
            reason(&s.open("wsh-host", || 999, true)),
            "too many open channels"
        );
    }

    #[test]
    fn close_of_a_pending_channel_is_claimed_and_its_stream_will_be_dropped() {
        let mut s = RpcSessions::new(Some(settings(false)), vec![]);
        assert!(matches!(
            s.open("wsh-host", || 5, true).payload,
            Payload::OpenOk(_)
        ));
        assert!(s.owns_channel(5));
        assert!(s.on_close(5), "claimed: not a session Close");
        assert!(!s.owns_channel(5));
        assert!(!s.on_close(5), "second close is not ours any more");
        assert!(!s.on_close(77));
    }

    // ── Over a real QMux pair ───────────────────────────────────────────

    use std::sync::Arc;
    use tokio::sync::mpsc::UnboundedReceiver;
    use wsh_core::qmux_connection::{QMuxConnection, QMuxConnectionConfig, QMuxEvent};

    struct Wire {
        client: Arc<QMuxConnection>,
        server: Arc<QMuxConnection>,
        client_events: UnboundedReceiver<QMuxEvent>,
        server_events: Option<UnboundedReceiver<QMuxEvent>>,
    }

    fn wire() -> Wire {
        let (c2s_tx, mut c2s_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (s2c_tx, mut s2c_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (client_ev_tx, client_events) = mpsc::unbounded_channel();
        let (server_ev_tx, server_events) = mpsc::unbounded_channel();
        let client = Arc::new(QMuxConnection::new(
            QMuxConnectionConfig {
                is_client: true,
                ..Default::default()
            },
            move |b: &[u8]| {
                let _ = c2s_tx.send(b.to_vec());
            },
            client_ev_tx,
        ));
        let server = Arc::new(QMuxConnection::new(
            QMuxConnectionConfig {
                is_client: false,
                ..Default::default()
            },
            move |b: &[u8]| {
                let _ = s2c_tx.send(b.to_vec());
            },
            server_ev_tx,
        ));
        let s = server.clone();
        tokio::spawn(async move {
            while let Some(b) = c2s_rx.recv().await {
                tokio::task::yield_now().await;
                s.receive_bytes(&b);
            }
        });
        let c = client.clone();
        tokio::spawn(async move {
            while let Some(b) = s2c_rx.recv().await {
                tokio::task::yield_now().await;
                c.receive_bytes(&b);
            }
        });
        client.send_handshake().unwrap();
        server.send_handshake().unwrap();
        Wire {
            client,
            server,
            client_events,
            server_events: Some(server_events),
        }
    }

    /// Run the glue the way the connection loop does, over the server end.
    fn drive(
        w: &mut Wire,
        sessions: Arc<tokio::sync::Mutex<RpcSessions>>,
    ) -> mpsc::Receiver<Envelope> {
        let (control_tx, control_rx) = mpsc::channel(16);
        let mut events = w.server_events.take().unwrap();
        let qmux = w.server.clone();
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                let mut s = sessions.lock().await;
                match ev {
                    QMuxEvent::StreamOpen { stream_id } => {
                        if !s.on_stream_open(stream_id, &qmux, control_tx.clone()) {
                            let _ = qmux.close_stream(stream_id);
                        }
                    }
                    QMuxEvent::StreamData { stream_id, data } => {
                        s.on_stream_data(stream_id, data);
                    }
                    QMuxEvent::StreamEnd { stream_id } => {
                        s.on_stream_end(stream_id);
                    }
                    QMuxEvent::StreamReset { stream_id, .. } => {
                        s.on_stream_reset(stream_id);
                    }
                    _ => {}
                }
            }
        });
        control_rx
    }

    async fn read_message(
        w: &mut Wire,
        stream_id: u64,
        dec: &mut super::super::seq::CborSequenceDecoder,
    ) -> Value {
        loop {
            let ev =
                tokio::time::timeout(std::time::Duration::from_secs(5), w.client_events.recv())
                    .await
                    .expect("timed out")
                    .expect("client events closed");
            if let QMuxEvent::StreamData {
                stream_id: id,
                data,
            } = ev
            {
                assert_eq!(id, stream_id);
                if let Some(v) = dec.feed(&data).unwrap().into_iter().next() {
                    return v;
                }
            }
        }
    }

    fn request(id: i64, method: &str) -> Vec<u8> {
        enc(&Value::Map(vec![
            (super::super::text("jsonrpc"), super::super::text("2.0")),
            (super::super::text("id"), super::super::int(id)),
            (super::super::text("method"), super::super::text(method)),
        ]))
    }

    #[tokio::test]
    async fn a_client_opened_stream_binds_in_openok_order_and_serves_requests() {
        let mut w = wire();
        let sessions = Arc::new(tokio::sync::Mutex::new(RpcSessions::new(
            Some(settings(false)),
            vec!["rpc".into(), "rpc-protocol:wsh-host".into()],
        )));
        sessions.lock().await.set_user("alice");
        let _control = drive(&mut w, sessions.clone());
        let first = matches!(
            sessions.lock().await.open("wsh-host", || 1, true).payload,
            Payload::OpenOk(_)
        );
        assert!(first);
        let sid = w.client.open_stream().await.unwrap();
        w.client
            .write_stream(sid, &request(1, "host.info"))
            .await
            .unwrap();
        let mut dec = super::super::seq::CborSequenceDecoder::new(1 << 20);
        let reply = read_message(&mut w, sid, &mut dec).await;
        let result = super::super::get(&reply, "result").expect("a result");
        assert_eq!(
            super::super::get(result, "user"),
            Some(&super::super::text("alice"))
        );
        assert_eq!(super::super::get(&reply, "id"), Some(&super::super::int(1)));
        w.client
            .write_stream(sid, &request(2, "host.ping"))
            .await
            .unwrap();
        let pong = read_message(&mut w, sid, &mut dec).await;
        assert!(super::super::get(super::super::get(&pong, "result").unwrap(), "time").is_some());
    }

    #[tokio::test]
    async fn a_stream_with_no_open_channel_is_closed_unbound() {
        let mut w = wire();
        let sessions = Arc::new(tokio::sync::Mutex::new(RpcSessions::new(
            Some(settings(false)),
            vec![],
        )));
        let _control = drive(&mut w, sessions);
        let sid = w.client.open_stream().await.unwrap();
        w.client.write_stream(sid, b"x").await.unwrap();
        loop {
            let ev =
                tokio::time::timeout(std::time::Duration::from_secs(5), w.client_events.recv())
                    .await
                    .expect("timed out")
                    .unwrap();
            if matches!(ev, QMuxEvent::StreamEnd { stream_id } if stream_id == sid) {
                break;
            }
        }
    }

    #[tokio::test]
    async fn the_client_finishing_its_stream_ends_the_channel_with_exit_and_close() {
        let mut w = wire();
        let sessions = Arc::new(tokio::sync::Mutex::new(RpcSessions::new(
            Some(settings(false)),
            vec![],
        )));
        let mut control = drive(&mut w, sessions.clone());
        sessions.lock().await.open("wsh-host", || 7, true);
        let sid = w.client.open_stream().await.unwrap();
        w.client
            .write_stream(sid, &request(1, "host.ping"))
            .await
            .unwrap();
        let mut dec = super::super::seq::CborSequenceDecoder::new(1 << 20);
        let _ = read_message(&mut w, sid, &mut dec).await;
        w.client.close_stream(sid).unwrap();
        let exit = tokio::time::timeout(std::time::Duration::from_secs(5), control.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(exit.payload, Payload::Exit(p) if p.channel_id == 7 && p.code == 0));
        let close = tokio::time::timeout(std::time::Duration::from_secs(5), control.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(close.payload, Payload::Close(p) if p.channel_id == 7));
    }

    #[tokio::test]
    async fn two_channels_bind_to_their_own_streams_in_order() {
        let mut w = wire();
        let sessions = Arc::new(tokio::sync::Mutex::new(RpcSessions::new(
            Some(settings(true)),
            vec![],
        )));
        let _control = drive(&mut w, sessions.clone());
        {
            let mut s = sessions.lock().await;
            s.open("wsh-host", || 1, true);
            s.open("wsh-fs", || 2, true);
        }
        // A client announces each stream as it opens it (the JS transport sends an empty STREAM frame), so the
        // server sees them in open order; here the first write plays that part.
        let host_stream = w.client.open_stream().await.unwrap();
        w.client
            .write_stream(host_stream, &request(1, "host.ping"))
            .await
            .unwrap();
        let mut dec = super::super::seq::CborSequenceDecoder::new(1 << 20);
        let r = read_message(&mut w, host_stream, &mut dec).await;
        assert!(super::super::get(&r, "result").is_some());

        let fs_stream = w.client.open_stream().await.unwrap();
        // host.ping exists only on the wsh-host channel, "list" only on wsh-fs
        w.client
            .write_stream(fs_stream, &request(1, "host.ping"))
            .await
            .unwrap();
        let mut dec2 = super::super::seq::CborSequenceDecoder::new(1 << 20);
        let r = read_message(&mut w, fs_stream, &mut dec2).await;
        assert_eq!(
            super::super::get(super::super::get(&r, "error").unwrap(), "code"),
            Some(&super::super::int(super::super::code::METHOD_NOT_FOUND))
        );
    }
}
