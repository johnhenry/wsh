//! Per-connection glue: binds `rpc` channels to client-opened QMux streams, or (virtual data mode) to `SessionData`.
//!
//! The flow mirrors an exec channel on the JS server. `Open { kind: "rpc" }` is
//! answered `OpenOk` (`data_mode: stream`); the client then opens one QMux
//! stream per channel, and streams bind to channels in `OpenOk` order. The
//! stream carries a CBOR sequence of JSON-RPC messages (see [`super::channel`]).
//!
//! With `seal_session` on (wsh #191) the connection is sealed and its bytes are frames, not streams: the same
//! CBOR sequence then rides `SessionData` (inside `EncryptedFrame`), answered `OpenOk` with `data_mode: virtual`,
//! and metered by `GatewayCredit` credit ([`wsh_core::rpc_credit`]) because the control plane has no flow control.

use super::channel::{self, ChannelConfig, Consumed, Ended, Input};
use super::protocols::{HostInfo, Protocol};
use super::{valid_protocol_name, RpcSettings, WSH_FS, WSH_HOST};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use wsh_core::messages::{
    ClosePayload, Envelope, ExitPayload, GatewayCreditPayload, MsgType, OpenFailPayload,
    OpenOkPayload, Payload, SessionDataMode, SessionDataPayload,
};
use wsh_core::qmux_connection::QMuxConnection;
use wsh_core::rpc_credit::{rpc_credit_id, CreditLink};

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
    // only a payload the strict decoder (#317) would also accept is an rpc Open
    wsh_core::cbor_strict::validate(raw).ok()?;
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
            stderr_channel_id: None,
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
    /// Virtual data mode: no stream; the credit link meters the bytes in both directions.
    Virtual {
        tx: mpsc::UnboundedSender<Input>,
        link: Arc<CreditLink>,
    },
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
        let handler = match self.resolve(protocol, allow_fs) {
            Ok(h) => h,
            Err(refusal) => return refusal,
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

    /// Whether this server states its rpc channels in virtual data mode (`rpc-virtual`): they ride `SessionData`
    /// instead of client-opened data streams, so [`open_virtual`](Self::open_virtual) opens them.
    pub fn is_virtual(&self) -> bool {
        self.settings.as_ref().is_some_and(|s| s.virtual_data)
    }

    /// Handle `Open { kind: "rpc", command: protocol }` in virtual data mode (wsh #191): the channel starts at once and
    /// everything it sends leaves as `SessionData` on `control` (and so inside the session's seal, when it has one),
    /// metered by credit; what it receives arrives through [`on_session_data`](Self::on_session_data) and
    /// [`on_credit`](Self::on_credit).
    ///
    /// The same checks as [`open`](Self::open): the protocol, the channel limit, and `allow_fs` (what the key's
    /// capabilities allow of `wsh-fs`; the caller has already applied `rpc:<protocol>`).
    pub fn open_virtual(
        &mut self,
        protocol: &str,
        mut alloc_channel_id: impl FnMut() -> u32,
        allow_fs: bool,
        control: mpsc::Sender<Envelope>,
    ) -> Envelope {
        let Some(settings) = self.settings.clone() else {
            return open_fail("UNSUPPORTED_PROTOCOL: rpc is not enabled on this server");
        };
        let handler = match self.resolve(protocol, allow_fs) {
            Ok(h) => h,
            Err(refusal) => return refusal,
        };
        let channel_id = alloc_channel_id();
        self.live.fetch_add(1, Ordering::Relaxed);
        let link = Arc::new(CreditLink::new());
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(32);
        self.channels.insert(
            channel_id,
            Channel::Virtual {
                tx: in_tx,
                link: link.clone(),
            },
        );

        // What the channel writes leaves as SessionData, a chunk at a time, each waiting for credit.
        let writer = {
            let (link, control) = (link.clone(), control.clone());
            tokio::spawn(async move {
                while let Some(bytes) = out_rx.recv().await {
                    let mut rest = &bytes[..];
                    while !rest.is_empty() {
                        let Ok(n) = link.reserve(rest.len()).await else {
                            return;
                        };
                        let chunk = Envelope {
                            msg_type: MsgType::SessionData,
                            payload: Payload::SessionData(SessionDataPayload {
                                channel_id,
                                data: rest[..n].to_vec(),
                            }),
                        };
                        if control.send(chunk).await.is_err() {
                            return;
                        }
                        rest = &rest[n..];
                    }
                }
            })
        };
        // What it takes in is credit handed back to the client.
        let consumed: Consumed = {
            let (link, control) = (link.clone(), control.clone());
            Box::new(move |n| {
                if let Some(give) = link.consumed(n) {
                    let credit = Envelope {
                        msg_type: MsgType::GatewayCredit,
                        payload: Payload::GatewayCredit(GatewayCreditPayload {
                            gateway_id: rpc_credit_id(channel_id),
                            bytes: u32::try_from(give).unwrap_or(u32::MAX),
                        }),
                    };
                    let control = control.clone();
                    tokio::spawn(async move {
                        let _ = control.send(credit).await;
                    });
                }
            })
        };
        let cfg = ChannelConfig {
            max_message_bytes: settings.max_message_bytes,
            max_inflight: settings.max_inflight,
        };
        let live = self.live.clone();
        tokio::spawn(async move {
            let overrun = {
                let link = link.clone();
                Box::new(move || link.is_closed()) as Box<dyn Fn() -> bool + Send + Sync>
            };
            let ended = channel::run_metered(
                cfg,
                Arc::new(handler),
                in_rx,
                out_tx,
                Some(consumed),
                Some(overrun),
            )
            .await;
            // Let what was queued reach the wire (bounded: the peer may be gone, or not granting credit).
            let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
            link.close();
            match &ended {
                Ended::HostClosed(why) => {
                    debug!(channel_id, why = %why, "rpc channel (virtual) closed by host")
                }
                other => debug!(channel_id, ?other, "rpc channel (virtual) ended"),
            }
            // The host ended it (a protocol error, or the peer overran its credit): tell the client the channel is over.
            if matches!(ended, Ended::HostClosed(_) | Ended::StreamEnd) {
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
            live.fetch_sub(1, Ordering::Relaxed);
        });
        debug!(channel_id, protocol, "rpc channel opened (virtual)");
        Envelope {
            msg_type: MsgType::OpenOk,
            payload: Payload::OpenOk(OpenOkPayload {
                channel_id,
                stream_ids: vec![],
                data_mode: SessionDataMode::Virtual,
                capabilities: vec![],
                session_id: None,
                token: None,
                stderr_channel_id: None,
            }),
        }
    }

    /// `SessionData` for a virtual-mode rpc channel: true if the channel is one (the caller must not treat the message
    /// as session input). A peer that sends more than the credit it was given has the channel closed.
    pub fn on_session_data(&self, channel_id: u32, data: Vec<u8>) -> bool {
        let Some(Channel::Virtual { tx, link }) = self.channels.get(&channel_id) else {
            return false;
        };
        if data.is_empty() {
            return true;
        }
        if link.receive(data.len()) {
            let _ = tx.send(Input::Data(data));
        } else {
            debug!(
                channel_id,
                "rpc channel: the peer sent more than its credit"
            );
            // The writer may be waiting on credit this peer will never grant, with the channel waiting on the writer:
            // release it, so the channel gets to the `Violation` and closes.
            link.close();
            let _ = tx.send(Input::Violation);
        }
        true
    }

    /// `GatewayCredit` for a virtual-mode rpc channel (`gateway_id` flagged): the peer took `bytes` in.
    pub fn on_credit(&self, channel_id: u32, bytes: u32) {
        if let Some(Channel::Virtual { link, .. }) = self.channels.get(&channel_id) {
            link.grant(u64::from(bytes));
        }
    }

    /// The handler for `protocol`, or the `OpenFail` to answer with.
    fn resolve(&self, protocol: &str, allow_fs: bool) -> Result<Protocol, Envelope> {
        let Some(settings) = self.settings.clone() else {
            return Err(open_fail(
                "UNSUPPORTED_PROTOCOL: rpc is not enabled on this server",
            ));
        };
        if self.live.load(Ordering::Relaxed) >= MAX_RPC_CHANNELS {
            return Err(open_fail("too many open channels"));
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
                Some(_) => return Err(open_fail("file transfer not permitted for this key")),
                None => None,
            }
        } else {
            None
        };
        handler.ok_or_else(|| {
            open_fail(format!(
                "UNSUPPORTED_PROTOCOL: protocol \"{protocol}\" is not supported by this server"
            ))
        })
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
            Some(Channel::Virtual { tx, link }) => {
                link.close();
                let _ = tx.send(Input::Kill);
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
        // strict since #317: an Open with a stray byte after it, or a non-shortest head, is not an rpc Open
        let mut stray = open_msg("rpc", Some("wsh-host"));
        stray.push(0x00);
        assert_eq!(peek_rpc_open(&stray), None);
        let mut padded = open_msg("rpc", Some("wsh-host"));
        let kind = padded.windows(4).position(|w| w == b"kind").unwrap();
        assert_eq!(padded[kind - 1], 0x64);
        padded[kind - 1] = 0x78; // text(4) as text with a one-byte length: the same key in a longer head
        padded.insert(kind, 0x04);
        assert_eq!(peek_rpc_open(&padded), None);
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
            virtual_data: false,
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

    // ── virtual data mode (wsh #191) ──────────────────────────────────────

    fn virtual_settings(fs: bool) -> Arc<RpcSettings> {
        let mut s = (*settings(fs)).clone();
        s.virtual_data = true;
        Arc::new(s)
    }

    /// `host.ping` padded to about `n` bytes, so a stream of them is a stream of bytes to meter.
    fn padded_request(id: i64, n: usize) -> Vec<u8> {
        enc(&Value::Map(vec![
            (super::super::text("jsonrpc"), super::super::text("2.0")),
            (super::super::text("id"), super::super::int(id)),
            (
                super::super::text("method"),
                super::super::text("host.ping"),
            ),
            (
                super::super::text("params"),
                Value::Map(vec![(
                    super::super::text("pad"),
                    super::super::text(&"p".repeat(n)),
                )]),
            ),
        ]))
    }

    /// An open virtual channel and what the host wrote to the control stream.
    async fn open_virtual_channel(
        protocol: &str,
        allow_fs: bool,
    ) -> (RpcSessions, u32, mpsc::Receiver<Envelope>) {
        let mut s = RpcSessions::new(Some(virtual_settings(true)), vec!["rpc-virtual".into()]);
        let (control, rx) = mpsc::channel(1024);
        let ok = s.open_virtual(protocol, || 5, allow_fs, control);
        let Payload::OpenOk(p) = ok.payload else {
            panic!("expected OpenOk, got {ok:?}")
        };
        assert_eq!(p.data_mode, SessionDataMode::Virtual);
        assert!(p.stream_ids.is_empty());
        (s, p.channel_id, rx)
    }

    async fn next_data(rx: &mut mpsc::Receiver<Envelope>) -> Vec<u8> {
        let e = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the host wrote nothing")
            .expect("control closed");
        match e.payload {
            Payload::SessionData(d) => d.data,
            other => panic!("expected SessionData, got {other:?}"),
        }
    }

    #[test]
    fn a_sealed_server_states_rpc_virtual_instead_of_rpc() {
        let f = virtual_settings(true).features();
        assert_eq!(f[0], "rpc-virtual");
        assert!(!f.contains(&"rpc".to_string()));
        assert!(f.contains(&"rpc-protocol:wsh-host".to_string()));
        assert!(f.contains(&"rpc-protocol:wsh-fs".to_string()));
        assert!(f.iter().any(|x| x.starts_with("rpc-max-message:")));
        assert_eq!(
            settings(true).features()[0],
            "rpc",
            "unsealed: stream mode, unchanged"
        );
        assert!(RpcSessions::new(Some(virtual_settings(false)), vec![]).is_virtual());
        assert!(!RpcSessions::new(Some(settings(false)), vec![]).is_virtual());
    }

    #[tokio::test]
    async fn a_virtual_channel_answers_requests_as_session_data() {
        let (s, ch, mut rx) = open_virtual_channel("wsh-host", true).await;
        assert!(s.on_session_data(ch, request(1, "host.ping")));
        let bytes = next_data(&mut rx).await;
        let mut dec = super::super::seq::CborSequenceDecoder::new(1 << 20);
        let r = dec.feed(&bytes).unwrap().remove(0);
        assert!(super::super::get(&r, "result").is_some());
        // SessionData for a channel that is not an rpc channel is not ours
        assert!(!s.on_session_data(ch + 1, request(1, "host.ping")));
    }

    #[tokio::test]
    async fn the_same_checks_apply_in_virtual_mode() {
        let mut s = RpcSessions::new(Some(virtual_settings(true)), vec![]);
        let (control, _rx) = mpsc::channel(8);
        // wsh-fs needs the file-transfer scope of the key
        assert_eq!(
            reason(&s.open_virtual("wsh-fs", || 1, false, control.clone())),
            "file transfer not permitted for this key"
        );
        assert!(reason(&s.open_virtual("mcp", || 1, true, control.clone()))
            .starts_with("UNSUPPORTED_PROTOCOL: protocol \"mcp\""));
        assert!(matches!(
            s.open_virtual("wsh-fs", || 2, true, control.clone())
                .payload,
            Payload::OpenOk(_)
        ));
        let mut off = RpcSessions::new(None, vec![]);
        assert_eq!(
            reason(&off.open_virtual("wsh-host", || 1, true, control)),
            "UNSUPPORTED_PROTOCOL: rpc is not enabled on this server"
        );
    }

    #[tokio::test]
    async fn credit_is_returned_as_the_channel_takes_requests_in() {
        let (s, ch, mut rx) = open_virtual_channel("wsh-host", true).await;
        // 40 requests of ~4 KiB are over half a window (128 KiB): credit comes back
        for i in 0..40 {
            assert!(s.on_session_data(ch, padded_request(i, 4000)));
        }
        let mut credited = 0u64;
        let mut answers = 0;
        while credited < 128 * 1024 {
            let e = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no credit came back")
                .unwrap();
            match e.payload {
                Payload::GatewayCredit(c) => {
                    assert_eq!(c.gateway_id, 0x8000_0000 | ch);
                    credited += u64::from(c.bytes);
                }
                Payload::SessionData(_) => answers += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(credited >= 128 * 1024 && answers > 0);
    }

    #[tokio::test]
    async fn a_client_that_overruns_its_credit_has_the_channel_closed() {
        let (s, ch, mut rx) = open_virtual_channel("wsh-host", true).await;
        // 5 x 64 KiB is over the 256 KiB window the client was given. The filler is a run of one-character strings, each
        // answered with an error the client never makes room for: the channel is stuck on its way out, and the overrun
        // still closes it.
        let filler = vec![0x61u8; 64 * 1024];
        for _ in 0..5 {
            s.on_session_data(ch, filler.clone());
        }
        // Wait for the event, not for a quiet moment: the host writes whatever answers it had ready, then Exit and Close,
        // and drops its end of the control stream once it is done (so `recv` returns `None` if Close never comes). How
        // long that takes depends on the machine; the outer timeout only keeps a broken build from hanging the suite.
        let closed = tokio::time::timeout(Duration::from_secs(120), async {
            while let Some(e) = rx.recv().await {
                if matches!(e.payload, Payload::Close(ref c) if c.channel_id == ch) {
                    return true;
                }
            }
            false
        })
        .await
        .expect("the channel neither closed nor ended");
        assert!(closed, "the host closes the channel (Exit, then Close)");
    }

    #[tokio::test]
    async fn the_client_closing_ends_a_virtual_channel_and_it_is_forgotten() {
        let (mut s, ch, _rx) = open_virtual_channel("wsh-host", true).await;
        assert!(s.owns_channel(ch));
        assert!(s.on_close(ch));
        assert!(!s.on_session_data(ch, request(1, "host.ping")));
        s.on_credit(ch, 10); // for a channel that is gone: ignored
    }
}
