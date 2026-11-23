//! The client side of the gateway: connections opened THROUGH the host (`OpenTcp`, `OpenUnix`,
//! `OpenEndpoint`) and listeners the host holds for us (`ListenRequest`, `ListenUnix`), with
//! `GatewayCredit` flow control.
//!
//! A [`GatewayStream`] is one open connection: `read` and `write_all` work from two tasks at once,
//! `shutdown` half-closes (`GatewayClose`), and [`GatewayStream::pump`] joins it to any local
//! stream with the right half-close handling in both directions.
//!
//! Flow control (feature `gateway-credit`, used when both ends list it): each direction starts with
//! 256 KiB of credit. `write_all` sends only while it holds credit and waits otherwise; `read`
//! returns credit to the host as the application takes data, so a reader that stops reading stops
//! the host's origin instead of growing a buffer here. A host that sends beyond the credit it was
//! given is closed on. With a host that predates the feature nothing is metered on the wire and
//! the received-but-unread bytes are bounded by a per-connection and a per-client cap instead
//! (the same numbers as the Node client): a connection that exceeds either is closed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use wsh_core::gateway_credit::{SendCredit, GATEWAY_CREDIT_WINDOW, GATEWAY_MAX_FRAME};
use wsh_core::messages::*;
use wsh_core::{frame_encode, WshError, WshResult};

/// Feature a host lists when `OpenUnix` / `ListenUnix` are available.
pub const GATEWAY_UNIX_FEATURE: &str = "gateway-unix";
/// Feature a host lists when `OpenEndpoint` is available.
pub const GATEWAY_ENDPOINTS_FEATURE: &str = "gateway-endpoints";
/// Feature a host lists when `OpenTcp` / `ListenRequest` are available.
pub const GATEWAY_FEATURE: &str = "gateway";
/// Re-exported for `Hello.features`.
pub use wsh_core::gateway_credit::GATEWAY_CREDIT_FEATURE as CREDIT_FEATURE;

/// Received bytes not yet read, per connection, before it is closed (no credit negotiated).
const MAX_QUEUED_PER_CONN: usize = 4 * 1024 * 1024;
/// The same over all of a client's connections.
const MAX_QUEUED_TOTAL: usize = 32 * 1024 * 1024;
/// How long to wait for the host to answer an open.
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

fn closed_error(reason: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, reason.to_string())
}

#[derive(Default)]
struct Inbox {
    chunks: VecDeque<Vec<u8>>,
    /// Bytes of the front chunk already handed out.
    front_off: usize,
    queued: usize,
}

/// State shared between the dispatch loop (which delivers what the host sends) and the
/// application (which reads and writes).
struct ConnShared {
    id: u32,
    hub: Weak<GatewayHub>,
    credit: bool,
    send: SendCredit,
    /// Bytes the host may still send before it overruns the credit we gave it.
    peer_window: AtomicI64,
    inbox: Mutex<Inbox>,
    data_ready: tokio::sync::Notify,
    unacked: AtomicUsize,
    remote_closed: AtomicBool,
    sent_close: AtomicBool,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
    closed_tx: watch::Sender<bool>,
}

impl ConnShared {
    fn new(id: u32, credit: bool, hub: Weak<GatewayHub>) -> Arc<Self> {
        Arc::new(Self {
            id,
            hub,
            credit,
            send: SendCredit::new(credit),
            peer_window: AtomicI64::new(if credit {
                GATEWAY_CREDIT_WINDOW as i64
            } else {
                0
            }),
            inbox: Mutex::new(Inbox::default()),
            data_ready: tokio::sync::Notify::new(),
            unacked: AtomicUsize::new(0),
            remote_closed: AtomicBool::new(false),
            sent_close: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            error: Mutex::new(None),
            closed_tx: watch::channel(false).0,
        })
    }

    fn hub(&self) -> Option<Arc<GatewayHub>> {
        self.hub.upgrade()
    }

    /// The host sent `data`.
    fn receive(&self, data: Vec<u8>) {
        let n = data.len();
        if n == 0
            || self.finished.load(Ordering::Acquire)
            || self.remote_closed.load(Ordering::Acquire)
        {
            return;
        }
        if self.credit {
            let left = self.peer_window.fetch_sub(n as i64, Ordering::AcqRel) - n as i64;
            if left < 0 {
                self.destroy(Some("host exceeded its credit"));
                return;
            }
        }
        let Some(hub) = self.hub() else { return };
        let total = hub.budget.fetch_add(n, Ordering::AcqRel) + n;
        let queued = {
            let mut inbox = self.inbox.lock().expect("inbox");
            inbox.queued += n;
            inbox.chunks.push_back(data);
            inbox.queued
        };
        if queued > MAX_QUEUED_PER_CONN || total > MAX_QUEUED_TOTAL {
            self.destroy(Some("receive buffer limit exceeded"));
            return;
        }
        self.data_ready.notify_one();
    }

    /// The host sent GatewayClose: no more data comes (what is queued can still be read).
    fn remote_closed(&self) {
        if self.remote_closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.data_ready.notify_one();
        self.send.wake();
        if self.sent_close.load(Ordering::Acquire) {
            self.retire();
        }
    }

    /// Both directions are done on the wire: the hub forgets the connection.
    fn retire(&self) {
        if let Some(hub) = self.hub() {
            hub.state.lock().expect("hub").conns.remove(&self.id);
        }
    }

    /// Close at once: GatewayClose goes out (if it had not), everything waiting is woken with an error.
    fn destroy(&self, reason: Option<&str>) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(r) = reason {
            *self.error.lock().expect("error") = Some(r.to_string());
        }
        if let Some(hub) = self.hub() {
            if !self.sent_close.swap(true, Ordering::AcqRel) {
                hub.send_nowait(Envelope {
                    msg_type: MsgType::GatewayClose,
                    payload: Payload::GatewayClose(GatewayClosePayload {
                        gateway_id: self.id,
                        reason: reason.map(str::to_string),
                    }),
                });
            }
            hub.state.lock().expect("hub").conns.remove(&self.id);
            let queued = {
                let mut inbox = self.inbox.lock().expect("inbox");
                inbox.chunks.clear();
                inbox.front_off = 0;
                std::mem::take(&mut inbox.queued)
            };
            hub.budget.fetch_sub(
                queued.min(hub.budget.load(Ordering::Acquire)),
                Ordering::AcqRel,
            );
        }
        let _ = self.closed_tx.send(true);
        self.data_ready.notify_one();
        self.send.wake();
    }

    fn io_error(&self) -> std::io::Error {
        let reason = self.error.lock().expect("error").clone();
        closed_error(reason.as_deref().unwrap_or("gateway connection closed"))
    }
}

/// One connection through the host. Cheap to clone; clones are the same connection, so one task
/// can read while another writes. Dropping the last clone closes it.
#[derive(Clone)]
pub struct GatewayStream {
    shared: Arc<ConnShared>,
    guard: Arc<DropClose>,
    /// Where the host says the connection came from (listeners) or went to (TCP), if it said.
    peer: Arc<Option<String>>,
}

struct DropClose(Arc<ConnShared>);
impl Drop for DropClose {
    fn drop(&mut self) {
        self.0.destroy(None);
    }
}

impl GatewayStream {
    fn new(shared: Arc<ConnShared>, peer: Option<String>) -> Self {
        Self {
            guard: Arc::new(DropClose(shared.clone())),
            shared,
            peer: Arc::new(peer),
        }
    }

    /// The `gateway_id` of this connection.
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// The peer address the host reported (`resolved_addr` for an outbound TCP connection, the
    /// connecting address for one accepted by a listener), if any.
    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    /// Is flow control in use on this connection?
    pub fn credit_negotiated(&self) -> bool {
        self.shared.credit
    }

    /// Read what the host sent. `Ok(0)` is the end: the host closed its side.
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let s = &self.shared;
        loop {
            // The lock is released before anything is awaited.
            let taken = {
                let mut inbox = s.inbox.lock().expect("inbox");
                let off = inbox.front_off;
                match inbox.chunks.front() {
                    Some(front) => {
                        let n = (front.len() - off).min(buf.len());
                        buf[..n].copy_from_slice(&front[off..off + n]);
                        let finished_chunk = off + n == front.len();
                        if finished_chunk {
                            inbox.chunks.pop_front();
                            inbox.front_off = 0;
                        } else {
                            inbox.front_off = off + n;
                        }
                        inbox.queued -= n;
                        Some(n)
                    }
                    None => None,
                }
            };
            if let Some(n) = taken {
                self.consumed(n).await;
                return Ok(n);
            }
            if s.finished.load(Ordering::Acquire) {
                let failed = s.error.lock().expect("error").is_some();
                return if failed { Err(s.io_error()) } else { Ok(0) };
            }
            if s.remote_closed.load(Ordering::Acquire) {
                return Ok(0);
            }
            s.data_ready.notified().await;
        }
    }

    /// The application took `n` bytes: free the budget and top up the host.
    async fn consumed(&self, n: usize) {
        let s = &self.shared;
        let Some(hub) = s.hub() else { return };
        hub.budget
            .fetch_sub(n.min(hub.budget.load(Ordering::Acquire)), Ordering::AcqRel);
        if s.credit
            && !s.finished.load(Ordering::Acquire)
            && !s.remote_closed.load(Ordering::Acquire)
        {
            let total = s.unacked.fetch_add(n, Ordering::AcqRel) + n;
            if total >= GATEWAY_CREDIT_WINDOW / 2 {
                let give = s.unacked.swap(0, Ordering::AcqRel);
                if give > 0 {
                    s.peer_window.fetch_add(give as i64, Ordering::AcqRel);
                    hub.send(Envelope {
                        msg_type: MsgType::GatewayCredit,
                        payload: Payload::GatewayCredit(GatewayCreditPayload {
                            gateway_id: s.id,
                            bytes: give as u32,
                        }),
                    })
                    .await;
                }
            }
        }
    }

    /// Send all of `data`, waiting for credit (when metered) and for the transport.
    pub async fn write_all(&self, data: &[u8]) -> std::io::Result<()> {
        let s = &self.shared;
        let Some(hub) = s.hub() else {
            return Err(closed_error("client disconnected"));
        };
        let mut closed_rx = s.closed_tx.subscribe();
        let mut off = 0;
        while off < data.len() {
            let writable = || {
                !(s.finished.load(Ordering::Acquire)
                    || s.sent_close.load(Ordering::Acquire)
                    || s.remote_closed.load(Ordering::Acquire))
            };
            if !writable() {
                return Err(if s.finished.load(Ordering::Acquire) {
                    s.io_error()
                } else {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gateway connection closed")
                });
            }
            let want = (data.len() - off).min(GATEWAY_MAX_FRAME);
            let n = tokio::select! {
                n = s.send.take(want) => n,
                _ = closed_rx.wait_for(|c| *c) => return Err(s.io_error()),
            };
            if !writable() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "gateway connection closed",
                ));
            }
            hub.send_checked(Envelope {
                msg_type: MsgType::GatewayData,
                payload: Payload::GatewayData(GatewayDataPayload {
                    gateway_id: s.id,
                    data: data[off..off + n].to_vec(),
                }),
            })
            .await
            .map_err(|_| closed_error("client disconnected"))?;
            off += n;
        }
        Ok(())
    }

    /// Half-close: nothing more will be sent. The host's origin may still answer; keep reading
    /// until `read` returns 0.
    pub async fn shutdown(&self) {
        let s = &self.shared;
        if s.finished.load(Ordering::Acquire) || s.sent_close.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(hub) = s.hub() {
            hub.send(Envelope {
                msg_type: MsgType::GatewayClose,
                payload: Payload::GatewayClose(GatewayClosePayload {
                    gateway_id: s.id,
                    reason: None,
                }),
            })
            .await;
        }
        if s.remote_closed.load(Ordering::Acquire) {
            s.retire();
        }
    }

    /// Tear the connection down now.
    pub fn destroy(&self) {
        self.shared.destroy(None);
    }

    /// Has the connection ended on the wire (the host closed and we did, or it was destroyed)?
    pub fn is_closed(&self) -> bool {
        self.shared.finished.load(Ordering::Acquire)
    }

    /// Join this connection to a local stream, both ways, until both directions have ended. An
    /// end on one side is passed on as a half-close to the other (the local side's EOF becomes
    /// `GatewayClose`, the host's end shuts the local write side), so a request/response
    /// exchange that closes its write side after the request still gets its answer.
    ///
    /// Returns the bytes moved `(local -> host, host -> local)`.
    pub async fn pump<L>(self, local: L) -> std::io::Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut lr, mut lw) = tokio::io::split(local);
        let up = {
            let me = self.clone();
            async move {
                let mut buf = vec![0u8; GATEWAY_MAX_FRAME];
                let mut total = 0u64;
                loop {
                    match lr.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if me.write_all(&buf[..n]).await.is_err() {
                                // The host is gone: nothing to feed, and nothing to wait for.
                                return Ok(total);
                            }
                            total += n as u64;
                        }
                        Err(e) => {
                            me.destroy();
                            return Err(e);
                        }
                    }
                }
                me.shutdown().await;
                Ok::<u64, std::io::Error>(total)
            }
        };
        let down = {
            let me = self.clone();
            async move {
                let mut buf = vec![0u8; GATEWAY_MAX_FRAME];
                let mut total = 0u64;
                loop {
                    match me.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if lw.write_all(&buf[..n]).await.is_err() {
                                me.destroy();
                                return Ok(total);
                            }
                            total += n as u64;
                        }
                        Err(e) => {
                            let _ = lw.shutdown().await;
                            return Err(e);
                        }
                    }
                }
                let _ = lw.shutdown().await;
                Ok::<u64, std::io::Error>(total)
            }
        };
        // The host ending its side ends the exchange, even if the local side is still open and
        // quiet (the OpenSSH behaviour): the local reader would otherwise wait for input forever.
        let mut up = Box::pin(up);
        let mut down = Box::pin(down);
        let (u, d) = tokio::select! {
            d = &mut down => {
                // Give an in-flight write a moment to finish, then stop reading local input.
                let u = tokio::time::timeout(Duration::from_millis(200), &mut up).await.unwrap_or(Ok(0));
                (u, d)
            }
            u = &mut up => {
                let d = (&mut down).await;
                (u, d)
            }
        };
        drop(self);
        Ok((u.unwrap_or(0), d?))
    }
}

/// An inbound connection a listener accepted on the host, not yet answered.
pub struct PendingInbound {
    hub: Arc<GatewayHub>,
    /// The id the host gave this connection.
    pub channel_id: u32,
    /// The connecting address as the host reports it (`"unix"` for a unix socket).
    pub peer_addr: String,
    /// The connecting port (0 for a unix socket).
    pub peer_port: u16,
}

impl PendingInbound {
    /// Take the connection.
    pub async fn accept(self) -> WshResult<GatewayStream> {
        let id = self.hub.alloc_id()?;
        let shared = ConnShared::new(
            id,
            self.hub.credit.load(Ordering::Acquire),
            Arc::downgrade(&self.hub),
        );
        // Registered BEFORE the host is told, so data that follows cannot beat it.
        self.hub
            .state
            .lock()
            .expect("hub")
            .conns
            .insert(id, shared.clone());
        self.hub
            .send_checked(Envelope {
                msg_type: MsgType::InboundAccept,
                payload: Payload::InboundAccept(InboundAcceptPayload {
                    channel_id: self.channel_id,
                    gateway_id: Some(id),
                }),
            })
            .await?;
        Ok(GatewayStream::new(
            shared,
            Some(if self.peer_port == 0 {
                self.peer_addr.clone()
            } else {
                format!("{}:{}", self.peer_addr, self.peer_port)
            }),
        ))
    }

    /// Refuse it: the host closes the connection.
    pub async fn reject(self, reason: &str) {
        self.hub
            .send(Envelope {
                msg_type: MsgType::InboundReject,
                payload: Payload::InboundReject(InboundRejectPayload {
                    channel_id: self.channel_id,
                    reason: Some(reason.to_string()),
                }),
            })
            .await;
    }
}

/// A listener the host holds for us.
pub struct GatewayListener {
    hub: Arc<GatewayHub>,
    listener_id: u32,
    actual_port: u16,
    rx: mpsc::UnboundedReceiver<InboundOpenPayload>,
}

impl GatewayListener {
    /// The port the host bound (0 for a unix socket).
    pub fn actual_port(&self) -> u16 {
        self.actual_port
    }

    /// The next connection the host accepted, or `None` once the listener is closed.
    pub async fn next(&mut self) -> Option<PendingInbound> {
        let open = self.rx.recv().await?;
        Some(PendingInbound {
            hub: self.hub.clone(),
            channel_id: open.channel_id,
            peer_addr: open.peer_addr,
            peer_port: open.peer_port,
        })
    }

    /// Stop listening (the host removes the socket it made).
    pub async fn close(self) {
        self.hub.close_listener(self.listener_id).await;
    }
}

impl Drop for GatewayListener {
    fn drop(&mut self) {
        let hub = self.hub.clone();
        let id = self.listener_id;
        if hub
            .state
            .lock()
            .expect("hub")
            .listeners
            .remove(&id)
            .is_some()
        {
            hub.send_nowait(Envelope {
                msg_type: MsgType::ListenClose,
                payload: Payload::ListenClose(ListenClosePayload { listener_id: id }),
            });
        }
    }
}

type OpenReply = Result<(), (u32, String)>;

#[derive(Default)]
struct HubState {
    /// Opens waiting for GatewayOk / GatewayFail.
    pending: HashMap<
        u32,
        (
            Arc<ConnShared>,
            oneshot::Sender<(OpenReply, Option<String>)>,
        ),
    >,
    conns: HashMap<u32, Arc<ConnShared>>,
    pending_listen: HashMap<u32, oneshot::Sender<Result<u16, String>>>,
    listeners: HashMap<u32, mpsc::UnboundedSender<InboundOpenPayload>>,
}

/// Every gateway connection and listener of one client connection.
pub(crate) struct GatewayHub {
    out: mpsc::Sender<Vec<u8>>,
    credit: AtomicBool,
    next_id: AtomicU32,
    budget: AtomicUsize,
    state: Mutex<HubState>,
}

impl Default for GatewayHub {
    /// A hub that is not connected to anything (tests).
    fn default() -> Self {
        Self::new(mpsc::channel(1).0)
    }
}

impl GatewayHub {
    pub(crate) fn new(out: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            out,
            credit: AtomicBool::new(false),
            next_id: AtomicU32::new(1),
            budget: AtomicUsize::new(0),
            state: Mutex::new(HubState::default()),
        }
    }

    /// Credit is on when the host advertised `gateway-credit` (we always list it in `Hello`).
    pub(crate) fn set_credit(&self, on: bool) {
        self.credit.store(on, Ordering::Release);
    }

    async fn send(&self, envelope: Envelope) {
        if let Ok(frame) = frame_encode(&envelope) {
            let _ = self.out.send(frame).await;
        }
    }

    async fn send_checked(&self, envelope: Envelope) -> WshResult<()> {
        let frame = frame_encode(&envelope)?;
        self.out
            .send(frame)
            .await
            .map_err(|_| WshError::Transport("outgoing channel closed".into()))
    }

    /// Queue a frame from a place that cannot await (a drop); a full queue spawns the send.
    fn send_nowait(self: &Arc<Self>, envelope: Envelope) {
        let Ok(frame) = frame_encode(&envelope) else {
            return;
        };
        match self.out.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(frame)) => {
                let out = self.out.clone();
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.spawn(async move {
                        let _ = out.send(frame).await;
                    });
                }
            }
            Err(_) => {}
        }
    }

    fn alloc_id(&self) -> WshResult<u32> {
        let state = self.state.lock().expect("hub");
        for _ in 0..64 {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !state.conns.contains_key(&id) && !state.pending.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(WshError::Other("no free gateway id".into()))
    }

    /// Open a connection: `build` makes the Open* message for the id.
    pub(crate) async fn open(
        self: &Arc<Self>,
        build: impl FnOnce(u32) -> Envelope,
    ) -> WshResult<GatewayStream> {
        let id = self.alloc_id()?;
        let shared = ConnShared::new(
            id,
            self.credit.load(Ordering::Acquire),
            Arc::downgrade(self),
        );
        let (tx, rx) = oneshot::channel();
        self.state
            .lock()
            .expect("hub")
            .pending
            .insert(id, (shared.clone(), tx));
        // If this future is dropped or times out, the entry goes with it.
        struct Pending(Arc<GatewayHub>, u32);
        impl Drop for Pending {
            fn drop(&mut self) {
                self.0.state.lock().expect("hub").pending.remove(&self.1);
            }
        }
        let _pending = Pending(self.clone(), id);
        self.send_checked(build(id)).await?;
        match tokio::time::timeout(OPEN_TIMEOUT, rx).await {
            Ok(Ok((Ok(()), resolved))) => Ok(GatewayStream::new(shared, resolved)),
            Ok(Ok((Err((code, message)), _))) => Err(gateway_failure(code, &message)),
            Ok(Err(_)) => Err(WshError::Transport("connection closed".into())),
            Err(_) => Err(WshError::Timeout),
        }
    }

    pub(crate) async fn listen(
        self: &Arc<Self>,
        build: impl FnOnce(u32) -> Envelope,
    ) -> WshResult<GatewayListener> {
        let listener_id = self.alloc_id()?;
        let (tx, rx) = oneshot::channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        {
            let mut state = self.state.lock().expect("hub");
            state.pending_listen.insert(listener_id, tx);
            // Registered now: an InboundOpen can follow ListenOk in the same burst.
            state.listeners.insert(listener_id, inbound_tx);
        }
        let cleanup = |hub: &GatewayHub| {
            let mut state = hub.state.lock().expect("hub");
            state.pending_listen.remove(&listener_id);
            state.listeners.remove(&listener_id);
        };
        if let Err(e) = self.send_checked(build(listener_id)).await {
            cleanup(self);
            return Err(e);
        }
        match tokio::time::timeout(OPEN_TIMEOUT, rx).await {
            Ok(Ok(Ok(actual_port))) => Ok(GatewayListener {
                hub: self.clone(),
                listener_id,
                actual_port,
                rx: inbound_rx,
            }),
            Ok(Ok(Err(reason))) => {
                cleanup(self);
                Err(WshError::Other(format!("host refused to listen: {reason}")))
            }
            Ok(Err(_)) => {
                cleanup(self);
                Err(WshError::Transport("connection closed".into()))
            }
            Err(_) => {
                cleanup(self);
                Err(WshError::Timeout)
            }
        }
    }

    async fn close_listener(&self, listener_id: u32) {
        let had = self
            .state
            .lock()
            .expect("hub")
            .listeners
            .remove(&listener_id)
            .is_some();
        if had {
            self.send(Envelope {
                msg_type: MsgType::ListenClose,
                payload: Payload::ListenClose(ListenClosePayload { listener_id }),
            })
            .await;
        }
    }

    /// Is this message one of ours? `false` leaves it for the rest of the client (a reverse
    /// host's own gateway traffic, for instance).
    pub(crate) async fn on_message(self: &Arc<Self>, envelope: &Envelope) -> bool {
        match &envelope.payload {
            Payload::GatewayOk(ok) => {
                let entry = self
                    .state
                    .lock()
                    .expect("hub")
                    .pending
                    .remove(&ok.gateway_id);
                match entry {
                    Some((shared, tx)) => {
                        // Registered before the opener is woken, so the data that follows in the
                        // same burst finds it.
                        self.state
                            .lock()
                            .expect("hub")
                            .conns
                            .insert(ok.gateway_id, shared);
                        let _ = tx.send((Ok(()), ok.resolved_addr.clone()));
                    }
                    None => {
                        // Nobody is waiting any more (the open timed out): close it again.
                        self.send_nowait(Envelope {
                            msg_type: MsgType::GatewayClose,
                            payload: Payload::GatewayClose(GatewayClosePayload {
                                gateway_id: ok.gateway_id,
                                reason: Some("open abandoned".into()),
                            }),
                        });
                    }
                }
                true
            }
            Payload::GatewayFail(f) => {
                let entry = self
                    .state
                    .lock()
                    .expect("hub")
                    .pending
                    .remove(&f.gateway_id);
                match entry {
                    Some((_, tx)) => {
                        let _ = tx.send((Err((f.code, f.message.clone())), None));
                        true
                    }
                    None => false,
                }
            }
            Payload::GatewayData(d) => {
                let conn = self
                    .state
                    .lock()
                    .expect("hub")
                    .conns
                    .get(&d.gateway_id)
                    .cloned();
                match conn {
                    Some(c) => {
                        c.receive(d.data.clone());
                        true
                    }
                    None => false,
                }
            }
            Payload::GatewayCredit(c) => {
                let conn = self
                    .state
                    .lock()
                    .expect("hub")
                    .conns
                    .get(&c.gateway_id)
                    .cloned();
                match conn {
                    Some(conn) => {
                        if conn.credit {
                            conn.send.grant(c.bytes);
                        }
                        true
                    }
                    None => false,
                }
            }
            Payload::GatewayClose(c) => {
                let conn = self
                    .state
                    .lock()
                    .expect("hub")
                    .conns
                    .get(&c.gateway_id)
                    .cloned();
                match conn {
                    Some(conn) => {
                        conn.remote_closed();
                        true
                    }
                    None => false,
                }
            }
            Payload::ListenOk(ok) => {
                let tx = self
                    .state
                    .lock()
                    .expect("hub")
                    .pending_listen
                    .remove(&ok.listener_id);
                match tx {
                    Some(tx) => {
                        let _ = tx.send(Ok(ok.actual_port));
                        true
                    }
                    None => false,
                }
            }
            Payload::ListenFail(f) => {
                let tx = self
                    .state
                    .lock()
                    .expect("hub")
                    .pending_listen
                    .remove(&f.listener_id);
                match tx {
                    Some(tx) => {
                        let _ = tx.send(Err(f.reason.clone()));
                        true
                    }
                    None => false,
                }
            }
            Payload::InboundOpen(o) => {
                let tx = self
                    .state
                    .lock()
                    .expect("hub")
                    .listeners
                    .get(&o.listener_id)
                    .cloned();
                match tx {
                    Some(tx) => {
                        if tx.send(o.clone()).is_err() {
                            self.send(Envelope {
                                msg_type: MsgType::InboundReject,
                                payload: Payload::InboundReject(InboundRejectPayload {
                                    channel_id: o.channel_id,
                                    reason: Some("listener closed".into()),
                                }),
                            })
                            .await;
                        }
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        }
    }

    /// The connection to the host is gone: end everything.
    pub(crate) fn close_all(&self) {
        let (conns, pending): (Vec<_>, Vec<_>) = {
            let mut state = self.state.lock().expect("hub");
            state.listeners.clear();
            state.pending_listen.clear();
            (
                state.conns.drain().map(|(_, c)| c).collect(),
                state.pending.drain().map(|(_, p)| p).collect(),
            )
        };
        for c in conns {
            // Nothing can be sent any more; mark it sent so no close is attempted.
            c.sent_close.store(true, Ordering::Release);
            c.destroy(Some("connection to the host closed"));
        }
        drop(pending);
    }
}

fn gateway_failure(code: u32, message: &str) -> WshError {
    let what = match code {
        1 => "connection refused",
        2 => "host unreachable",
        3 => "name lookup failed",
        4 => "refused by the host's policy",
        5 => "the host's gateway is disabled",
        7 => "too many gateway connections",
        _ => "gateway failure",
    };
    if message.is_empty() {
        WshError::Other(format!("{what} (gateway code {code})"))
    } else {
        WshError::Other(format!("{message} ({what}, gateway code {code})"))
    }
}

/// Does the host's feature list allow what is being asked? `Err` says what is missing, readably.
pub(crate) fn require_feature(features: &[String], feature: &str, what: &str) -> WshResult<()> {
    if features.iter().any(|f| f == feature) {
        Ok(())
    } else {
        Err(WshError::Other(format!(
            "this host does not offer {what} (its features do not include \"{feature}\")"
        )))
    }
}

/// Build `Open*` messages.
pub(crate) fn open_tcp_msg(id: u32, host: &str, port: u16) -> Envelope {
    Envelope {
        msg_type: MsgType::OpenTcp,
        payload: Payload::OpenTcp(OpenTcpPayload {
            gateway_id: id,
            host: host.to_string(),
            port,
        }),
    }
}

pub(crate) fn open_unix_msg(id: u32, path: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::OpenUnix,
        payload: Payload::OpenUnix(OpenUnixPayload {
            gateway_id: id,
            path: path.to_string(),
        }),
    }
}

pub(crate) fn open_endpoint_msg(id: u32, name: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::OpenEndpoint,
        payload: Payload::OpenEndpoint(OpenEndpointPayload {
            gateway_id: id,
            name: name.to_string(),
        }),
    }
}

pub(crate) fn listen_unix_msg(id: u32, path: &str, replace: bool) -> Envelope {
    Envelope {
        msg_type: MsgType::ListenUnix,
        payload: Payload::ListenUnix(ListenUnixPayload {
            listener_id: id,
            path: path.to_string(),
            replace: replace.then_some(true),
        }),
    }
}

pub(crate) fn listen_tcp_msg(id: u32, port: u16, bind_addr: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::ListenRequest,
        payload: Payload::ListenRequest(ListenRequestPayload {
            listener_id: id,
            port,
            bind_addr: bind_addr.to_string(),
        }),
    }
}

/// The named-endpoint name rule of the spec: letters, digits, `.`, `_`, `-`; at most 64; starts
/// with a letter or digit.
pub fn valid_endpoint_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && name.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests;
