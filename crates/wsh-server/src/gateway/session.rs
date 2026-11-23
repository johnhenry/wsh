//! The gateway of ONE client connection: its open TCP / UDP / unix-socket connections, its
//! reverse listeners, and the flow control between them and the client.
//!
//! Everything here belongs to a single authenticated connection and goes away with it; a
//! `gateway_id` or `listener_id` means nothing to any other client (the previous shared tables
//! let one client name, and close, another's).
//!
//! # Flow control (`GatewayCredit`, feature `gateway-credit`)
//!
//! When the client listed `gateway-credit` in `Hello.features` (and this host, having a gateway,
//! advertised it) each direction of each connection starts with 256 KiB of credit:
//!
//! * origin -> client: the relay task reads the origin only while it holds credit, so a client that
//!   stops reading stops the origin instead of growing a buffer here. The client's `GatewayCredit`
//!   tops it up.
//! * client -> origin: data is queued for the origin's writer; credit goes back to the client as the
//!   origin takes it. A client that sends beyond the credit it was given has broken the protocol and
//!   its connection is closed.
//!
//! Without the feature (an older peer) nothing is metered on the wire and a client can send as fast
//! as the transport lets it, so the buffering is bounded by byte caps instead
//! (`max_buffered_bytes` per connection, `max_client_buffered_bytes` per client): a connection that
//! exceeds either is closed. The same numbers as the Node host.
//!
//! `GatewayClose` is a half-close: the side that sends it sends no more data and goes on receiving
//! until the peer's own `GatewayClose` arrives (the origin gets 1 s after the client's before the
//! connection is torn down), exactly as the Node host does.

use super::forwarder::GatewayForwarder;
use super::policy::{ConnectionGuard, GatewayPolicyEnforcer};
use super::unix_policy::{self, SocketStat, UnixTarget};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};
use wsh_core::messages::*;

use wsh_core::gateway_credit::SendCredit;
pub use wsh_core::gateway_credit::{GATEWAY_CREDIT_FEATURE, GATEWAY_CREDIT_WINDOW};
/// Advertised when unix sockets are configured.
pub const GATEWAY_UNIX_FEATURE: &str = "gateway-unix";

/// Largest `GatewayData` payload this host sends.
const MAX_FRAME: usize = 65_536;
/// Largest `GatewayData` payload this host accepts (a bigger one is ignored, as the Node host does).
const MAX_DATA_BYTES: usize = 1024 * 1024;
/// After the client's `GatewayClose`, how long the origin has to finish before the connection is dropped.
const HALF_CLOSE_GRACE: Duration = Duration::from_secs(1);
const MAX_PENDING_INBOUND: usize = 16;
const INBOUND_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DATAGRAM: usize = 65_507;

// GatewayFail codes (the table `@johnhenry/browsermesh-netway` decodes).
const FAIL_REFUSED: u32 = 1;
const FAIL_UNREACHABLE: u32 = 2;
const FAIL_POLICY: u32 = 4;
const FAIL_DISABLED: u32 = 5;
const FAIL_QUEUE_FULL: u32 = 7;

/// Any byte stream a relay can carry: TCP, a unix socket, a boxed one.
pub trait RelayStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayStream for T {}
type BoxStream = Box<dyn RelayStream>;

fn ok(gateway_id: u32, resolved_addr: Option<String>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayOk,
        payload: Payload::GatewayOk(GatewayOkPayload {
            gateway_id,
            resolved_addr,
        }),
    }
}

fn fail(gateway_id: u32, code: u32, message: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayFail,
        payload: Payload::GatewayFail(GatewayFailPayload {
            gateway_id,
            code,
            message: message.chars().take(200).collect(),
        }),
    }
}

fn listen_fail(listener_id: u32, reason: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::ListenFail,
        payload: Payload::ListenFail(ListenFailPayload {
            listener_id,
            reason: reason.chars().take(200).collect(),
        }),
    }
}

fn listen_ok(listener_id: u32, actual_port: u16) -> Envelope {
    Envelope {
        msg_type: MsgType::ListenOk,
        payload: Payload::ListenOk(ListenOkPayload {
            listener_id,
            actual_port,
        }),
    }
}

fn data_msg(gateway_id: u32, data: Vec<u8>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayData,
        payload: Payload::GatewayData(GatewayDataPayload { gateway_id, data }),
    }
}

fn credit_msg(gateway_id: u32, bytes: u32) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayCredit,
        payload: Payload::GatewayCredit(GatewayCreditPayload { gateway_id, bytes }),
    }
}

fn close_msg(gateway_id: u32, reason: Option<&str>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayClose,
        payload: Payload::GatewayClose(GatewayClosePayload {
            gateway_id,
            reason: reason.map(str::to_string),
        }),
    }
}

enum WriteCmd {
    Data(Vec<u8>),
    Shutdown,
}

/// One open connection.
struct Chan {
    id: u32,
    /// Credit negotiated on this client connection.
    credit: bool,
    /// Credit this host holds to send origin data to the client.
    send: SendCredit,
    /// Bytes the client may still send before it has overrun the credit it was given.
    peer_window: AtomicI64,
    /// Bytes received from the client and not yet taken by the origin.
    queued: AtomicUsize,
    /// Bytes the origin took that the client has not been told about yet.
    unacked: AtomicUsize,
    finished: AtomicBool,
    sent_close: AtomicBool,
    /// The client sent GatewayClose: it sends no more.
    remote_closed: AtomicBool,
    write_tx: mpsc::UnboundedSender<WriteCmd>,
    tasks: Mutex<Vec<AbortHandle>>,
    guard: Mutex<Option<ConnectionGuard>>,
}

impl Chan {
    /// Take `n` bytes off `queued` (never below zero, whoever else is subtracting).
    fn release(&self, n: usize) -> usize {
        let mut cur = self.queued.load(Ordering::Acquire);
        loop {
            let take = cur.min(n);
            match self.queued.compare_exchange_weak(
                cur,
                cur - take,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return take,
                Err(now) => cur = now,
            }
        }
    }
}

struct PendingInbound {
    stream: BoxStream,
    listener_id: u32,
    timer: AbortHandle,
}

struct Listener {
    task: AbortHandle,
    /// A socket file this listener created, and what it looked like when it did.
    socket: Option<(PathBuf, Option<SocketStat>)>,
    /// Channel ids accepted on it and not yet answered.
    pending: HashSet<u32>,
}

struct Inner {
    policy: Arc<GatewayPolicyEnforcer>,
    forwarder: GatewayForwarder,
    out: mpsc::Sender<Envelope>,
    /// `[gateway] enabled`.
    enabled: bool,
    /// `gateway-credit` negotiated.
    credit: bool,
    max_conn_bytes: usize,
    max_client_bytes: usize,
    /// Bytes received from this client for its origins and not yet taken.
    budget: AtomicUsize,
    conns: Mutex<HashMap<u32, Arc<Chan>>>,
    /// gateway_ids whose connect is still in flight.
    reserved: Mutex<HashSet<u32>>,
    inbound: Mutex<HashMap<u32, PendingInbound>>,
    next_inbound: AtomicU32,
    listeners: Mutex<HashMap<u32, Listener>>,
    pending_listeners: Mutex<HashSet<u32>>,
    closed: AtomicBool,
}

/// The gateway of one client connection. Dropping it closes everything it opened.
pub struct GatewaySession {
    inner: Arc<Inner>,
}

impl Drop for GatewaySession {
    fn drop(&mut self) {
        self.inner.close_all();
    }
}

impl GatewaySession {
    /// * `out`: where messages for the client go (the connection's outbound queue).
    /// * `enabled`: `[gateway] enabled`; a disabled gateway answers every request with a refusal.
    /// * `client_features`: what the client listed in `Hello.features`.
    pub fn new(
        policy: Arc<GatewayPolicyEnforcer>,
        out: mpsc::Sender<Envelope>,
        enabled: bool,
        client_features: &[String],
    ) -> Self {
        let (max_conn_bytes, max_client_bytes) = policy.buffer_limits();
        let credit = enabled && client_features.iter().any(|f| f == GATEWAY_CREDIT_FEATURE);
        Self {
            inner: Arc::new(Inner {
                forwarder: GatewayForwarder::new(policy.clone()),
                policy,
                out,
                enabled,
                credit,
                max_conn_bytes,
                max_client_bytes,
                budget: AtomicUsize::new(0),
                conns: Mutex::new(HashMap::new()),
                reserved: Mutex::new(HashSet::new()),
                inbound: Mutex::new(HashMap::new()),
                next_inbound: AtomicU32::new(1),
                listeners: Mutex::new(HashMap::new()),
                pending_listeners: Mutex::new(HashSet::new()),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Is `msg_type` one this session serves?
    pub fn serves(msg_type: MsgType) -> bool {
        matches!(
            msg_type,
            MsgType::OpenTcp
                | MsgType::OpenUdp
                | MsgType::OpenUnix
                | MsgType::OpenEndpoint
                | MsgType::ResolveDns
                | MsgType::ListenRequest
                | MsgType::ListenUnix
                | MsgType::ListenClose
                | MsgType::InboundAccept
                | MsgType::InboundReject
                | MsgType::GatewayData
                | MsgType::GatewayCredit
                | MsgType::GatewayClose
        )
    }

    /// Is credit in use on this connection?
    pub fn credit_negotiated(&self) -> bool {
        self.inner.credit
    }

    /// Open connections (for tests and logs).
    pub fn open_connections(&self) -> usize {
        self.inner.conns.lock().expect("conns").len()
    }

    /// Bytes received from the client and not yet taken by an origin.
    pub fn buffered_bytes(&self) -> usize {
        self.inner.budget.load(Ordering::Acquire)
    }

    /// Handle one gateway message. Answers go out through the connection's outbound queue, never
    /// inline, so a slow connect does not hold up the session loop.
    pub fn handle(&self, envelope: Envelope) {
        let inner = self.inner.clone();
        if inner.closed.load(Ordering::Acquire) {
            return;
        }
        match envelope.payload {
            Payload::OpenTcp(p) => inner.start_open(p.gateway_id, move |i, id, guard| async move {
                i.open_tcp(id, guard, &p.host, p.port).await
            }),
            Payload::OpenUdp(p) => inner.start_open(p.gateway_id, move |i, id, guard| async move {
                i.open_udp(id, guard, &p.host, p.port).await
            }),
            Payload::OpenUnix(p) => inner
                .start_open(p.gateway_id, move |i, id, guard| async move {
                    i.open_unix(id, guard, &p.path).await
                }),
            Payload::OpenEndpoint(p) => {
                // This host has no named endpoints; say so instead of leaving the client waiting.
                inner.spawn_reply(fail(
                    p.gateway_id,
                    if inner.enabled {
                        FAIL_POLICY
                    } else {
                        FAIL_DISABLED
                    },
                    "no such endpoint",
                ));
            }
            Payload::ResolveDns(p) => {
                if !inner.enabled {
                    inner.spawn_reply(fail(p.gateway_id, FAIL_DISABLED, "gateway disabled"));
                    return;
                }
                tokio::spawn(async move {
                    let reply = inner
                        .forwarder
                        .handle_resolve_dns(p.gateway_id, &p.name, &p.record_type)
                        .await;
                    inner.send(reply).await;
                });
            }
            Payload::ListenRequest(p) => {
                tokio::spawn(async move {
                    let reply = inner.listen_tcp(p.listener_id, p.port, &p.bind_addr).await;
                    inner.send(reply).await;
                });
            }
            Payload::ListenUnix(p) => {
                tokio::spawn(async move {
                    let reply = inner
                        .listen_unix(p.listener_id, &p.path, p.replace == Some(true))
                        .await;
                    inner.send(reply).await;
                });
            }
            Payload::ListenClose(p) => {
                if inner.close_listener(p.listener_id) {
                    inner.spawn_reply(Envelope {
                        msg_type: MsgType::ListenClose,
                        payload: Payload::ListenClose(ListenClosePayload {
                            listener_id: p.listener_id,
                        }),
                    });
                }
            }
            Payload::InboundAccept(p) => match p.gateway_id {
                Some(gateway_id) => inner.inbound_accept(p.channel_id, gateway_id),
                None => debug!(
                    channel_id = p.channel_id,
                    "InboundAccept without gateway_id, ignoring"
                ),
            },
            Payload::InboundReject(p) => inner.inbound_reject(p.channel_id),
            Payload::GatewayData(p) => inner.on_data(p.gateway_id, p.data),
            Payload::GatewayCredit(p) => {
                if inner.credit {
                    if let Some(chan) = inner.chan(p.gateway_id) {
                        chan.send.grant(p.bytes);
                    }
                }
            }
            Payload::GatewayClose(p) => inner.on_remote_close(p.gateway_id),
            _ => {}
        }
    }
}

impl Inner {
    fn chan(&self, id: u32) -> Option<Arc<Chan>> {
        self.conns.lock().expect("conns").get(&id).cloned()
    }

    async fn send(&self, envelope: Envelope) {
        let _ = self.out.send(envelope).await;
    }

    fn spawn_reply(self: &Arc<Self>, envelope: Envelope) {
        let inner = self.clone();
        tokio::spawn(async move { inner.send(envelope).await });
    }

    /// Reserve `id` and the connection slot, then run `open` in its own task.
    fn start_open<F, Fut>(self: &Arc<Self>, id: u32, open: F)
    where
        F: FnOnce(Arc<Inner>, u32, ConnectionGuard) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), (u32, String)>> + Send + 'static,
    {
        if !self.enabled {
            self.spawn_reply(fail(id, FAIL_DISABLED, "gateway disabled"));
            return;
        }
        {
            let conns = self.conns.lock().expect("conns");
            let mut reserved = self.reserved.lock().expect("reserved");
            if conns.contains_key(&id) || reserved.contains(&id) {
                drop(reserved);
                drop(conns);
                self.spawn_reply(fail(id, FAIL_POLICY, "gateway_id already in use"));
                return;
            }
            reserved.insert(id);
        }
        let guard = match self.policy.try_acquire() {
            Ok(g) => g,
            Err(reason) => {
                self.reserved.lock().expect("reserved").remove(&id);
                self.spawn_reply(fail(id, FAIL_QUEUE_FULL, &reason));
                return;
            }
        };
        let inner = self.clone();
        tokio::spawn(async move {
            let result = open(inner.clone(), id, guard).await;
            inner.reserved.lock().expect("reserved").remove(&id);
            match result {
                Ok(()) => {}
                Err((code, message)) => inner.send(fail(id, code, &message)).await,
            }
        });
    }

    // ── opening ─────────────────────────────────────────────────────

    async fn open_tcp(
        self: &Arc<Self>,
        id: u32,
        guard: ConnectionGuard,
        host: &str,
        port: u16,
    ) -> Result<(), (u32, String)> {
        let addrs = self.forwarder.authorized_destination(host, port).await?;
        let stream = match super::forwarder::connect_first(&addrs).await {
            Ok(s) => s,
            Err(e) => {
                warn!(gateway_id = id, host, port, error = %e, "TCP connect failed");
                return Err((FAIL_REFUSED, e.to_string()));
            }
        };
        let _ = stream.set_nodelay(true);
        let resolved = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        info!(gateway_id = id, addr = %format!("{host}:{port}"), "TCP connection established");
        // Register the connection BEFORE the client hears GatewayOk, and send nothing from the
        // origin before the Ok is queued.
        let ready = self.attach_stream(id, Box::new(stream), guard);
        self.send(ok(id, Some(resolved))).await;
        ready.notify_one();
        Ok(())
    }

    async fn open_unix(
        self: &Arc<Self>,
        id: u32,
        guard: ConnectionGuard,
        requested: &str,
    ) -> Result<(), (u32, String)> {
        let unix = self.policy.unix();
        if unix.connect.is_empty() {
            return Err((
                FAIL_POLICY,
                "unix sockets are not enabled on this gateway".into(),
            ));
        }
        let target = match unix_policy::check_unix_path(requested, &unix.connect).await {
            Ok(t) => t,
            Err(reason) => {
                info!(path = %requested.chars().take(200).collect::<String>(), %reason, "unix connect refused");
                return Err((FAIL_POLICY, reason));
            }
        };
        let stream = match &target {
            UnixTarget::Path(path) => {
                match unix_policy::stat_socket(path).await {
                    Ok(None) => return Err((FAIL_REFUSED, "no such socket".into())),
                    Ok(Some(st)) if !st.is_socket => {
                        info!(path = %path.display(), "unix connect refused (not a socket)");
                        return Err((FAIL_POLICY, "not a socket".into()));
                    }
                    Ok(Some(_)) => {}
                    Err(e) => return Err((FAIL_UNREACHABLE, e.to_string())),
                }
                connect_unix_path(path).await?
            }
            UnixTarget::Abstract(name) => connect_unix_abstract(name).await?,
        };
        info!(gateway_id = id, path = %requested.chars().take(200).collect::<String>(), "unix connection established");
        let ready = self.attach_stream(id, stream, guard);
        self.send(ok(id, None)).await;
        ready.notify_one();
        Ok(())
    }

    async fn open_udp(
        self: &Arc<Self>,
        id: u32,
        guard: ConnectionGuard,
        host: &str,
        port: u16,
    ) -> Result<(), (u32, String)> {
        let addrs = self.forwarder.authorized_destination(host, port).await?;
        // The first address that passed: the socket must be of its family.
        let target = addrs[0];
        let local = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|e| (FAIL_REFUSED, e.to_string()))?;
        socket
            .connect(target)
            .await
            .map_err(|e| (FAIL_REFUSED, e.to_string()))?;
        info!(gateway_id = id, addr = %target, "UDP socket opened");
        let ready = self.attach_datagrams(id, socket, guard);
        self.send(ok(id, None)).await;
        ready.notify_one();
        Ok(())
    }

    // ── connection plumbing ─────────────────────────────────────────

    fn new_chan(
        &self,
        id: u32,
        guard: ConnectionGuard,
    ) -> (Arc<Chan>, mpsc::UnboundedReceiver<WriteCmd>) {
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let chan = Arc::new(Chan {
            id,
            credit: self.credit,
            send: SendCredit::new(self.credit),
            peer_window: AtomicI64::new(if self.credit {
                GATEWAY_CREDIT_WINDOW as i64
            } else {
                0
            }),
            queued: AtomicUsize::new(0),
            unacked: AtomicUsize::new(0),
            finished: AtomicBool::new(false),
            sent_close: AtomicBool::new(false),
            remote_closed: AtomicBool::new(false),
            write_tx,
            tasks: Mutex::new(Vec::new()),
            guard: Mutex::new(Some(guard)),
        });
        self.conns.lock().expect("conns").insert(id, chan.clone());
        (chan, write_rx)
    }

    /// Start the relay tasks of a connected stream. The returned `Notify` releases the origin-reading
    /// task: it must not send data before the client has been told the connection is open.
    fn attach_stream(
        self: &Arc<Self>,
        id: u32,
        stream: BoxStream,
        guard: ConnectionGuard,
    ) -> Arc<Notify> {
        let (chan, write_rx) = self.new_chan(id, guard);
        let (rd, wr) = tokio::io::split(stream);
        let ready = Arc::new(Notify::new());
        let reader = {
            let inner = self.clone();
            let chan = chan.clone();
            let ready = ready.clone();
            tokio::spawn(async move {
                ready.notified().await;
                inner.read_loop(chan, rd).await;
            })
        };
        let writer = {
            let inner = self.clone();
            let chan = chan.clone();
            tokio::spawn(async move { inner.write_loop(chan, wr, write_rx).await })
        };
        chan.tasks
            .lock()
            .expect("tasks")
            .extend([reader.abort_handle(), writer.abort_handle()]);
        ready
    }

    /// Origin -> client, one chunk at a time: the origin is read only while credit is held.
    async fn read_loop(self: Arc<Self>, chan: Arc<Chan>, mut rd: tokio::io::ReadHalf<BoxStream>) {
        let mut buf = vec![0u8; MAX_FRAME];
        'outer: loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut off = 0;
            while off < n {
                let allowed = chan.send.take((n - off).min(MAX_FRAME)).await;
                if self
                    .out
                    .send(data_msg(chan.id, buf[off..off + allowed].to_vec()))
                    .await
                    .is_err()
                {
                    break 'outer;
                }
                off += allowed;
            }
        }
        // The origin is done: tell the client once everything it sent has gone out.
        self.destroy(&chan, None);
    }

    /// Client -> origin. Credit goes back to the client as the origin takes the bytes.
    async fn write_loop(
        self: Arc<Self>,
        chan: Arc<Chan>,
        mut wr: tokio::io::WriteHalf<BoxStream>,
        mut rx: mpsc::UnboundedReceiver<WriteCmd>,
    ) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                WriteCmd::Data(data) => {
                    let n = data.len();
                    if wr.write_all(&data).await.is_err() {
                        self.destroy(&chan, Some("write failed"));
                        return;
                    }
                    self.consumed(&chan, n).await;
                }
                WriteCmd::Shutdown => {
                    let _ = wr.shutdown().await;
                }
            }
        }
    }

    /// The origin took `n` bytes: free them from the queue and the budget, and top up the client.
    async fn consumed(&self, chan: &Arc<Chan>, n: usize) {
        let freed = chan.release(n);
        self.budget.fetch_sub(
            freed.min(self.budget.load(Ordering::Acquire)),
            Ordering::AcqRel,
        );
        if chan.credit
            && !chan.finished.load(Ordering::Acquire)
            && !chan.remote_closed.load(Ordering::Acquire)
        {
            let total = chan.unacked.fetch_add(n, Ordering::AcqRel) + n;
            if total >= GATEWAY_CREDIT_WINDOW / 2 {
                let give = chan.unacked.swap(0, Ordering::AcqRel);
                if give > 0 {
                    chan.peer_window.fetch_add(give as i64, Ordering::AcqRel);
                    let _ = self.out.send(credit_msg(chan.id, give as u32)).await;
                }
            }
        }
    }

    fn attach_datagrams(
        self: &Arc<Self>,
        id: u32,
        socket: UdpSocket,
        guard: ConnectionGuard,
    ) -> Arc<Notify> {
        let (chan, mut write_rx) = self.new_chan(id, guard);
        let socket = Arc::new(socket);
        let ready = Arc::new(Notify::new());
        let reader = {
            let inner = self.clone();
            let chan = chan.clone();
            let socket = socket.clone();
            let ready = ready.clone();
            tokio::spawn(async move {
                ready.notified().await;
                let mut buf = vec![0u8; MAX_DATAGRAM + 1];
                loop {
                    let got = tokio::time::timeout(UDP_IDLE_TIMEOUT, socket.recv(&mut buf)).await;
                    match got {
                        Ok(Ok(n)) => {
                            // A datagram the client has no credit for is dropped, as a network would.
                            if chan.send.try_take_exact(n)
                                && inner
                                    .out
                                    .send(data_msg(chan.id, buf[..n].to_vec()))
                                    .await
                                    .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
                inner.destroy(&chan, None);
            })
        };
        let writer = {
            let inner = self.clone();
            let chan = chan.clone();
            tokio::spawn(async move {
                while let Some(cmd) = write_rx.recv().await {
                    if let WriteCmd::Data(data) = cmd {
                        let n = data.len();
                        if n <= MAX_DATAGRAM {
                            let _ = socket.send(&data).await;
                        }
                        inner.consumed(&chan, n).await;
                    }
                }
            })
        };
        chan.tasks
            .lock()
            .expect("tasks")
            .extend([reader.abort_handle(), writer.abort_handle()]);
        ready
    }

    /// Tear a connection down: tell the client (once), stop the tasks, give the slot back.
    fn destroy(self: &Arc<Self>, chan: &Arc<Chan>, reason: Option<&str>) {
        if chan.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if !chan.sent_close.swap(true, Ordering::AcqRel) && !self.closed.load(Ordering::Acquire) {
            self.spawn_reply(close_msg(chan.id, reason));
        }
        {
            let mut conns = self.conns.lock().expect("conns");
            if conns.get(&chan.id).is_some_and(|c| Arc::ptr_eq(c, chan)) {
                conns.remove(&chan.id);
            }
        }
        let rest = chan.queued.swap(0, Ordering::AcqRel);
        if rest > 0 {
            let cur = self.budget.load(Ordering::Acquire);
            self.budget.fetch_sub(rest.min(cur), Ordering::AcqRel);
        }
        for task in chan.tasks.lock().expect("tasks").drain(..) {
            task.abort();
        }
        chan.guard.lock().expect("guard").take();
    }

    // ── from the client ─────────────────────────────────────────────

    fn on_data(self: &Arc<Self>, id: u32, data: Vec<u8>) {
        let Some(chan) = self.chan(id) else { return };
        let n = data.len();
        if n == 0 || n > MAX_DATA_BYTES || chan.finished.load(Ordering::Acquire) {
            return;
        }
        if chan.remote_closed.load(Ordering::Acquire) {
            return;
        }
        if chan.credit {
            let left = chan.peer_window.fetch_sub(n as i64, Ordering::AcqRel) - n as i64;
            if left < 0 {
                warn!(
                    gateway_id = id,
                    "client exceeded its gateway credit, closing the connection"
                );
                self.destroy(&chan, Some("peer exceeded its credit"));
                return;
            }
        }
        let queued = chan.queued.fetch_add(n, Ordering::AcqRel) + n;
        let total = self.budget.fetch_add(n, Ordering::AcqRel) + n;
        if queued > self.max_conn_bytes || total > self.max_client_bytes {
            warn!(
                gateway_id = id,
                queued, total, "gateway buffer limit exceeded, closing the connection"
            );
            self.destroy(&chan, Some("buffer limit exceeded"));
            return;
        }
        let _ = chan.write_tx.send(WriteCmd::Data(data));
    }

    /// The client sent GatewayClose: it sends no more. The origin may still answer for a moment.
    fn on_remote_close(self: &Arc<Self>, id: u32) {
        let Some(chan) = self.chan(id) else { return };
        if chan.remote_closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = chan.write_tx.send(WriteCmd::Shutdown);
        let inner = self.clone();
        let grace = tokio::spawn(async move {
            tokio::time::sleep(HALF_CLOSE_GRACE).await;
            inner.destroy(&chan, Some("grace period over"));
        });
        if let Some(c) = self.chan(id) {
            c.tasks.lock().expect("tasks").push(grace.abort_handle());
        }
    }

    // ── reverse listeners ───────────────────────────────────────────

    async fn listen_tcp(
        self: &Arc<Self>,
        listener_id: u32,
        port: u16,
        bind_addr: &str,
    ) -> Envelope {
        if !self.enabled {
            return listen_fail(listener_id, "gateway disabled");
        }
        if self.listener_in_use(listener_id) {
            return listen_fail(listener_id, "listener_id already in use");
        }
        if let Err(reason) = self.policy.check_listen(port) {
            return listen_fail(listener_id, &reason);
        }
        // The listener binds where the server's configuration says (loopback unless
        // `[gateway] reverse_bind_addr` is set), never where the client asks: its `bind_addr`
        // defaults to "0.0.0.0", which would publish the port on every interface of this machine.
        let bound_to = self.policy.reverse_bind_addr();
        if bind_addr.parse::<std::net::IpAddr>().ok() != Some(bound_to) {
            debug!(listener_id, requested = %bind_addr, bound = %bound_to, "ignoring the client's bind_addr: reverse listeners bind to the configured address");
        }
        let addr = SocketAddr::new(bound_to, port);
        let guard = match self.policy.try_acquire() {
            Ok(g) => g,
            Err(reason) => return listen_fail(listener_id, &reason),
        };
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(listener_id, %addr, error = %e, "listen bind failed");
                return listen_fail(listener_id, &e.to_string());
            }
        };
        let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
        info!(listener_id, %addr, actual_port, "reverse tunnel listener started");
        let inner = self.clone();
        let task = tokio::spawn(async move {
            let _guard = guard; // counted while the listener lives
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        inner
                            .announce_inbound(
                                listener_id,
                                Box::new(stream),
                                peer.ip().to_string(),
                                peer.port(),
                            )
                            .await;
                    }
                    Err(e) => {
                        warn!(listener_id, error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
        self.listeners.lock().expect("listeners").insert(
            listener_id,
            Listener {
                task: task.abort_handle(),
                socket: None,
                pending: HashSet::new(),
            },
        );
        listen_ok(listener_id, actual_port)
    }

    fn listener_in_use(&self, id: u32) -> bool {
        self.listeners.lock().expect("listeners").contains_key(&id)
            || self
                .pending_listeners
                .lock()
                .expect("pending")
                .contains(&id)
    }

    async fn listen_unix(
        self: &Arc<Self>,
        listener_id: u32,
        requested: &str,
        replace: bool,
    ) -> Envelope {
        if !self.enabled {
            return listen_fail(listener_id, "gateway disabled");
        }
        if self.listener_in_use(listener_id) {
            return listen_fail(listener_id, "listener_id already in use");
        }
        let unix = self.policy.unix();
        if unix.listen.is_empty() {
            return listen_fail(
                listener_id,
                "unix listeners are not enabled on this gateway",
            );
        }
        let count = self.listeners.lock().expect("listeners").len()
            + self.pending_listeners.lock().expect("pending").len();
        if count >= unix.max_listeners {
            return listen_fail(listener_id, "too many unix listeners");
        }
        self.pending_listeners
            .lock()
            .expect("pending")
            .insert(listener_id);
        let result = self
            .listen_unix_checked(listener_id, requested, replace)
            .await;
        self.pending_listeners
            .lock()
            .expect("pending")
            .remove(&listener_id);
        match result {
            Ok(()) => listen_ok(listener_id, 0),
            Err(reason) => listen_fail(listener_id, &reason),
        }
    }

    #[cfg(unix)]
    async fn listen_unix_checked(
        self: &Arc<Self>,
        listener_id: u32,
        requested: &str,
        replace: bool,
    ) -> Result<(), String> {
        let unix = self.policy.unix();
        let target = unix_policy::check_unix_path(requested, &unix.listen)
            .await
            .map_err(|reason| {
                info!(path = %requested.chars().take(200).collect::<String>(), %reason, "unix listen refused");
                reason
            })?;
        let guard = self.policy.try_acquire()?;
        let (listener, socket): (
            tokio::net::UnixListener,
            Option<(PathBuf, Option<SocketStat>)>,
        ) = match target {
            UnixTarget::Path(path) => {
                if let Some(existing) = unix_policy::stat_socket(&path)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    if !existing.is_socket {
                        return Err("a file that is not a socket is in the way".into());
                    }
                    if !replace {
                        return Err(
                            "address in use (a socket file exists; ask to replace it)".into()
                        );
                    }
                    if !unix.replace_stale {
                        return Err(
                            "replacing an existing socket is not allowed by the gateway policy"
                                .into(),
                        );
                    }
                    // Only a stale socket: one nothing accepts connections on.
                    if socket_is_live(&path).await {
                        return Err("address in use (the existing socket is live)".into());
                    }
                    unix_policy::unlink_if_socket_sync(&path, Some(existing));
                }
                let listener = bind_private(&path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AddrInUse {
                        "address in use".to_string()
                    } else {
                        e.to_string()
                    }
                })?;
                let stat = unix_policy::stat_socket(&path).await.ok().flatten();
                (listener, Some((path, stat)))
            }
            UnixTarget::Abstract(name) => (bind_abstract(&name).map_err(|e| e.to_string())?, None),
        };
        if self.closed.load(Ordering::Acquire) {
            if let Some((path, stat)) = &socket {
                unix_policy::unlink_if_socket_sync(path, *stat);
            }
            return Err("connection closed".into());
        }
        info!(listener_id, path = %requested.chars().take(200).collect::<String>(), "listening on a unix socket");
        let inner = self.clone();
        let task = tokio::spawn(async move {
            let _guard = guard;
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        inner
                            .announce_inbound(listener_id, Box::new(stream), "unix".to_string(), 0)
                            .await;
                    }
                    Err(e) => {
                        warn!(listener_id, error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
        self.listeners.lock().expect("listeners").insert(
            listener_id,
            Listener {
                task: task.abort_handle(),
                socket,
                pending: HashSet::new(),
            },
        );
        Ok(())
    }

    #[cfg(not(unix))]
    async fn listen_unix_checked(
        self: &Arc<Self>,
        _listener_id: u32,
        _requested: &str,
        _replace: bool,
    ) -> Result<(), String> {
        Err("unix sockets are not available on this platform".into())
    }

    /// A connection arrived on a listener: hold it until the client says what to do with it.
    async fn announce_inbound(
        self: &Arc<Self>,
        listener_id: u32,
        stream: BoxStream,
        peer_addr: String,
        peer_port: u16,
    ) {
        let channel_id = {
            let mut inbound = self.inbound.lock().expect("inbound");
            if self.closed.load(Ordering::Acquire) || inbound.len() >= MAX_PENDING_INBOUND {
                return; // dropped: the connection is closed
            }
            let channel_id = self.next_inbound.fetch_add(1, Ordering::Relaxed);
            let inner = self.clone();
            let timer = tokio::spawn(async move {
                tokio::time::sleep(INBOUND_ACCEPT_TIMEOUT).await;
                inner.drop_pending(channel_id);
            });
            inbound.insert(
                channel_id,
                PendingInbound {
                    stream,
                    listener_id,
                    timer: timer.abort_handle(),
                },
            );
            channel_id
        };
        if let Some(l) = self
            .listeners
            .lock()
            .expect("listeners")
            .get_mut(&listener_id)
        {
            l.pending.insert(channel_id);
        }
        self.send(Envelope {
            msg_type: MsgType::InboundOpen,
            payload: Payload::InboundOpen(InboundOpenPayload {
                listener_id,
                channel_id,
                peer_addr,
                peer_port,
            }),
        })
        .await;
    }

    fn take_pending(&self, channel_id: u32) -> Option<PendingInbound> {
        let pending = self.inbound.lock().expect("inbound").remove(&channel_id)?;
        pending.timer.abort();
        if let Some(l) = self
            .listeners
            .lock()
            .expect("listeners")
            .get_mut(&pending.listener_id)
        {
            l.pending.remove(&channel_id);
        }
        Some(pending)
    }

    fn drop_pending(&self, channel_id: u32) {
        let _ = self.take_pending(channel_id);
    }

    fn inbound_reject(&self, channel_id: u32) {
        if self.take_pending(channel_id).is_none() {
            debug!(channel_id, "no pending connection for InboundReject");
        }
    }

    fn inbound_accept(self: &Arc<Self>, channel_id: u32, gateway_id: u32) {
        let Some(pending) = self.take_pending(channel_id) else {
            warn!(channel_id, "no pending connection for InboundAccept");
            return;
        };
        {
            let conns = self.conns.lock().expect("conns");
            if conns.contains_key(&gateway_id)
                || self
                    .reserved
                    .lock()
                    .expect("reserved")
                    .contains(&gateway_id)
            {
                return; // dropped: the id is taken
            }
        }
        let Ok(guard) = self.policy.try_acquire() else {
            return;
        };
        info!(channel_id, gateway_id, "inbound connection relay started");
        let ready = self.attach_stream(gateway_id, pending.stream, guard);
        ready.notify_one();
    }

    /// Stop a listener and remove the socket file it made. `true` when there was one.
    fn close_listener(&self, id: u32) -> bool {
        let Some(l) = self.listeners.lock().expect("listeners").remove(&id) else {
            return false;
        };
        self.stop_listener(l);
        true
    }

    fn stop_listener(&self, l: Listener) {
        l.task.abort();
        for ch in l.pending {
            self.drop_pending(ch);
        }
        if let Some((path, stat)) = l.socket {
            unix_policy::unlink_if_socket_sync(&path, stat);
        }
    }

    /// The connection is gone: close everything silently.
    fn close_all(self: &Arc<Self>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let chans: Vec<Arc<Chan>> = self
            .conns
            .lock()
            .expect("conns")
            .values()
            .cloned()
            .collect();
        for chan in chans {
            chan.sent_close.store(true, Ordering::Release);
            self.destroy(&chan, None);
        }
        let ids: Vec<u32> = self
            .inbound
            .lock()
            .expect("inbound")
            .keys()
            .copied()
            .collect();
        for id in ids {
            self.drop_pending(id);
        }
        let listeners: Vec<Listener> = self
            .listeners
            .lock()
            .expect("listeners")
            .drain()
            .map(|(_, l)| l)
            .collect();
        for l in listeners {
            self.stop_listener(l);
        }
    }
}

// ── unix socket helpers ───────────────────────────────────────────────

#[cfg(unix)]
async fn connect_unix_path(path: &std::path::Path) -> Result<BoxStream, (u32, String)> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(path)).await {
        Ok(Ok(s)) => Ok(Box::new(s)),
        Ok(Err(e)) => Err((
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                FAIL_REFUSED
            } else {
                FAIL_UNREACHABLE
            },
            e.to_string(),
        )),
        Err(_) => Err((FAIL_UNREACHABLE, "connect timed out".into())),
    }
}

#[cfg(not(unix))]
async fn connect_unix_path(_path: &std::path::Path) -> Result<BoxStream, (u32, String)> {
    Err((
        FAIL_POLICY,
        "unix sockets are not available on this platform".into(),
    ))
}

#[cfg(target_os = "linux")]
async fn connect_unix_abstract(name: &str) -> Result<BoxStream, (u32, String)> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|e| (FAIL_POLICY, e.to_string()))?;
    let std_stream = std::os::unix::net::UnixStream::connect_addr(&addr).map_err(|e| {
        (
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                FAIL_REFUSED
            } else {
                FAIL_UNREACHABLE
            },
            e.to_string(),
        )
    })?;
    std_stream
        .set_nonblocking(true)
        .map_err(|e| (FAIL_UNREACHABLE, e.to_string()))?;
    let s = tokio::net::UnixStream::from_std(std_stream)
        .map_err(|e| (FAIL_UNREACHABLE, e.to_string()))?;
    Ok(Box::new(s))
}

#[cfg(not(target_os = "linux"))]
async fn connect_unix_abstract(_name: &str) -> Result<BoxStream, (u32, String)> {
    Err((
        FAIL_POLICY,
        "abstract unix sockets exist only on Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
fn bind_abstract(name: &str) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let l = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    l.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(l)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn bind_abstract(_name: &str) -> std::io::Result<tokio::net::UnixListener> {
    Err(std::io::Error::other(
        "abstract unix sockets exist only on Linux",
    ))
}

/// Bind a unix socket that is private from the first instant: a socket's mode is the process umask
/// at bind time, so the umask is tightened around the one synchronous `bind` (nothing awaits in
/// between) and the mode is then set explicitly as well.
#[cfg(unix)]
fn bind_private(path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: umask only swaps a process-wide mask; it has no memory-safety preconditions.
    let old = unsafe { libc::umask(0o177) };
    let bound = std::os::unix::net::UnixListener::bind(path);
    unsafe { libc::umask(old) };
    let l = bound?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    l.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(l)
}

/// Does anything accept connections on this socket file? (Anything but a clear refusal counts as live.)
#[cfg(unix)]
async fn socket_is_live(path: &std::path::Path) -> bool {
    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::UnixStream::connect(path),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => !matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests;
