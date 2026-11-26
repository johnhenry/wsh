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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use wsh_core::gateway_credit::{
    SendCredit, GATEWAY_CREDIT_WINDOW, GATEWAY_DISCARDED, GATEWAY_MAX_FRAME,
};
use wsh_core::messages::*;
use wsh_core::peer_watch::PeerWatch;
pub use wsh_core::peer_watch::{WatchablePeer, DEFAULT_HALF_CLOSE_PROBE};
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
/// How long [`GatewayStream::pump`] lets a half-closed exchange sit with nothing moving in either
/// direction before it closes it (five minutes, the same as the host's `half_close_idle_secs`).
pub const DEFAULT_HALF_CLOSE_IDLE: Duration = Duration::from_secs(300);
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
    /// `discarded`: the host has dropped the connection and reads nothing more, so our direction is
    /// over too (writes fail; nothing is sent back).
    fn remote_closed(&self, discarded: bool) {
        if self.remote_closed.swap(true, Ordering::AcqRel) {
            // A SECOND close saying "discarded": the host had half-closed and has now lost its
            // reader. It reads nothing more, so the connection is over at once, as after a reset
            // (what it sent and nothing here has read is dropped); nothing goes back. Any other
            // repeated close is ignored, as it always was.
            if discarded && !self.sent_close.swap(true, Ordering::AcqRel) {
                self.destroy(None);
            }
            return;
        }
        if discarded {
            self.sent_close.store(true, Ordering::Release);
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
            // Not closed on our side yet: the close goes out now. Closed on our side already (a
            // half-close) while the host has not closed: it still holds its direction open for
            // us, so a SECOND close saying "discarded" tells it we read nothing more. When the
            // host had closed too the connection is over and nothing more is sent.
            let already = self.sent_close.swap(true, Ordering::AcqRel);
            if !already || !self.remote_closed.load(Ordering::Acquire) {
                let said = if already {
                    GATEWAY_DISCARDED
                } else {
                    reason.unwrap_or(GATEWAY_DISCARDED)
                };
                hub.send_nowait(Envelope {
                    msg_type: MsgType::GatewayClose,
                    payload: Payload::GatewayClose(GatewayClosePayload {
                        gateway_id: self.id,
                        reason: Some(said.to_string()),
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
        // `send_replace`: the value is kept even with no receiver now, so one that subscribes later still sees it.
        self.closed_tx.send_replace(true);
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
            // The host's GatewayClose is a half-close: it sends no more, and what we send still reaches its origin.
            let writable =
                || !(s.finished.load(Ordering::Acquire) || s.sent_close.load(Ordering::Acquire));
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
    ///
    /// A half-closed exchange (one side has finished, the other has not) stays open for as long as
    /// anything moves in either direction, so a request that closes its write side gets an answer
    /// however late it comes, and a host that closes first does not stop what the local side goes
    /// on to send. With nothing moving in either direction for [`DEFAULT_HALF_CLOSE_IDLE`] the
    /// connection is closed and `pump` returns a `TimedOut` error; see
    /// [`GatewayStream::pump_with_idle`] to choose the bound or turn it off.
    pub async fn pump<L>(self, local: L) -> std::io::Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        self.pump_with_idle(local, Some(DEFAULT_HALF_CLOSE_IDLE))
            .await
    }

    /// [`GatewayStream::pump`] with the bound on a half-closed exchange chosen (`None` = never).
    pub async fn pump_with_idle<L>(
        self,
        local: L,
        idle: Option<Duration>,
    ) -> std::io::Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        self.pump_inner(local, idle, None).await
    }

    /// [`GatewayStream::pump_with_idle`] for a local socket (TCP, or a unix stream) whose peer is
    /// WATCHED once it has half-closed (wsh #282): a local program that sent its end of file and was
    /// then killed gives a plain read loop nothing, so the host's connection and slot would be held
    /// until the far side next sent. The kernel does report it, as a hang-up of the socket's write
    /// side; with `probe` set that is awaited as soon as the local side's end of file is read, and
    /// the connection is then ended as a destroyed one (a second `GatewayClose` with the reason
    /// `discarded`) and `pump` returns an error of kind `ConnectionAborted`. Nothing is ever
    /// written to the local program. For a TCP socket `probe` is also the short keep-alive
    /// schedule given to the socket at that moment (see [`wsh_core::peer_watch`]: a peer that
    /// exited without unread data is noticed when its kernel drops the connection, about a minute).
    /// `None` = no watch (as `pump_with_idle`). Where the platform cannot watch (Windows) this is
    /// `pump_with_idle`.
    pub async fn pump_watched<L>(
        self,
        local: L,
        idle: Option<Duration>,
        probe: Option<Duration>,
    ) -> std::io::Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Send + 'static + WatchablePeer,
    {
        let watch = probe.and_then(|p| local.peer_watch().map(|w| (w, p)));
        self.pump_inner(local, idle, watch).await
    }

    async fn pump_inner<L>(
        self,
        local: L,
        idle: Option<Duration>,
        watch: Option<(PeerWatch, Duration)>,
    ) -> std::io::Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut lr, mut lw) = tokio::io::split(local);
        // Whether the local side's end of file has been read: the exchange is half-closed by it.
        let local_eof = Arc::new(AtomicBool::new(false));
        // Whether we have shut the local write side ourselves (the host's end reached us).
        let local_shut = Arc::new(AtomicBool::new(false));
        let started = std::time::Instant::now();
        // When a byte last moved either way (milliseconds since `started`), the bytes moved each
        // way, and whether either direction has finished (the exchange is half-closed).
        let last = Arc::new(AtomicU64::new(0));
        let up_bytes = Arc::new(AtomicU64::new(0));
        let down_bytes = Arc::new(AtomicU64::new(0));
        let half = Arc::new(watch::channel(false).0);
        let touch = {
            let last = last.clone();
            move || last.store(started.elapsed().as_millis() as u64, Ordering::Release)
        };
        let up = {
            let me = self.clone();
            let touch = touch.clone();
            let half = half.clone();
            let up_bytes = up_bytes.clone();
            let local_eof = local_eof.clone();
            async move {
                let mut closed = me.shared.closed_tx.subscribe();
                let mut buf = vec![0u8; GATEWAY_MAX_FRAME];
                let result = loop {
                    let read = tokio::select! {
                        r = lr.read(&mut buf) => r,
                        // The connection is gone (reset, idle, dropped): there is nobody to feed.
                        _ = closed.wait_for(|c| *c) => return Ok::<(), std::io::Error>(()),
                    };
                    match read {
                        Ok(0) => {
                            local_eof.store(true, Ordering::Release);
                            break Ok(());
                        }
                        Ok(n) => {
                            if me.write_all(&buf[..n]).await.is_err() {
                                // The host is gone: nothing to feed, and nothing to wait for.
                                return Ok(());
                            }
                            up_bytes.fetch_add(n as u64, Ordering::AcqRel);
                            touch();
                        }
                        Err(e) => {
                            me.destroy();
                            break Err(e);
                        }
                    }
                };
                half.send_replace(true);
                if result.is_ok() {
                    me.shutdown().await;
                }
                result
            }
        };
        let down = {
            let me = self.clone();
            let touch = touch.clone();
            let half = half.clone();
            let down_bytes = down_bytes.clone();
            let local_shut = local_shut.clone();
            async move {
                let mut buf = vec![0u8; GATEWAY_MAX_FRAME];
                let result = loop {
                    match me.read(&mut buf).await {
                        Ok(0) => break Ok(()),
                        Ok(n) => {
                            if lw.write_all(&buf[..n]).await.is_err() {
                                me.destroy();
                                half.send_replace(true);
                                return Ok::<(), std::io::Error>(());
                            }
                            down_bytes.fetch_add(n as u64, Ordering::AcqRel);
                            touch();
                        }
                        Err(e) => break Err(e),
                    }
                };
                half.send_replace(true);
                // From here the socket's write side is shut BY US, which is also a hang-up of it:
                // flagged first, so the watch does not take our own shutdown for the peer going away.
                local_shut.store(true, Ordering::Release);
                let _ = lw.shutdown().await;
                result
            }
        };
        // The idle rule: once one direction has finished, nothing moving in either direction for
        // `idle` ends the connection. (Not a fixed timer: a slow answer, or a local side that sends
        // late, is not cut off.)
        let watch_idle = {
            let half = half.clone();
            let last = last.clone();
            async move {
                let Some(idle) = idle else {
                    return std::future::pending::<()>().await;
                };
                let mut rx = half.subscribe();
                let _ = rx.wait_for(|h| *h).await;
                loop {
                    let quiet = Duration::from_millis(
                        (started.elapsed().as_millis() as u64)
                            .saturating_sub(last.load(Ordering::Acquire)),
                    );
                    match idle.checked_sub(quiet) {
                        None => return,
                        Some(left) => tokio::time::sleep(left).await,
                    }
                }
            }
        };
        // The local program half-closed and went away: the kernel's hang-up of the socket's write
        // side. Only awaited once the local side's end of file has been read (until then the socket
        // is an ordinary connection: no keep-alive change, no watch), and not once the exchange is
        // over from the host's side too (nothing then waits on the local program).
        let peer_gone = {
            let local_eof = local_eof.clone();
            let local_shut = local_shut.clone();
            async move {
                let Some((watch, every)) = watch else {
                    return std::future::pending::<()>().await;
                };
                // Polled only once the local feeder has finished (the guard below): by then the
                // flag says whether it ended on the local program's end of file or otherwise.
                if !local_eof.load(Ordering::Acquire) {
                    return std::future::pending::<()>().await;
                }
                watch.arm(every);
                watch.gone().await;
                if local_shut.load(Ordering::Acquire) {
                    // The hang-up is our own shutdown of the write side: the exchange is ending,
                    // the peer did not go away.
                    return std::future::pending::<()>().await;
                }
            }
        };
        let mut up = Box::pin(up);
        let mut down = Box::pin(down);
        let mut watch_idle = Box::pin(watch_idle);
        let mut peer_gone = Box::pin(peer_gone);
        let (mut up_done, mut down_done) = (false, false);
        let mut down_result: std::io::Result<()> = Ok(());
        let mut timed_out = false;
        let mut gone = false;
        while !(up_done && down_done) {
            tokio::select! {
                _ = &mut up, if !up_done => up_done = true,
                r = &mut down, if !down_done => { down_done = true; down_result = r; }
                _ = &mut watch_idle => { timed_out = true; break; }
                _ = &mut peer_gone, if up_done && !down_done => { gone = true; break; }
            }
        }
        if timed_out {
            self.destroy();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "a half-closed gateway connection had nothing moving in either direction",
            ));
        }
        if gone {
            // As a local socket that was destroyed: the host is told (a second close, "discarded").
            self.destroy();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the local peer went away after finishing its side",
            ));
        }
        drop(self);
        down_result?;
        Ok((
            up_bytes.load(Ordering::Acquire),
            down_bytes.load(Ordering::Acquire),
        ))
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
    /// Folders this client offers to the host (#159): the hub already holds the connection's
    /// outgoing sender and is told when the connection ends, which is all shares need.
    pub(crate) shares: crate::share::ShareHub,
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
            credit: AtomicBool::new(false),
            next_id: AtomicU32::new(1),
            budget: AtomicUsize::new(0),
            state: Mutex::new(HubState::default()),
            shares: crate::share::ShareHub::new(out.clone()),
            out,
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
                        conn.remote_closed(c.reason.as_deref() == Some(GATEWAY_DISCARDED));
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
            Payload::ShareRequest(_) => self.shares.on_message(envelope),
            _ => false,
        }
    }

    /// The connection to the host is gone: end everything.
    pub(crate) fn close_all(&self) {
        self.shares.shutdown();
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

/// The name of a `GatewayFail` code, as in `spec/gateway-fail.vectors.json`; `None` for a number
/// that is not in the table.
#[cfg_attr(not(test), allow(dead_code))]
fn gateway_fail_name(code: u32) -> Option<&'static str> {
    Some(match code {
        1 => "CONNECTION_REFUSED",
        2 => "HOST_UNREACHABLE",
        3 => "DNS_FAILED",
        4 => "POLICY_DENIED",
        5 => "GATEWAY_DISABLED",
        6 => "CLOSED",
        7 => "QUEUE_FULL",
        8 => "TIMEOUT",
        _ => return None,
    })
}

fn gateway_failure(code: u32, message: &str) -> WshError {
    let what = match code {
        1 => "connection refused",
        2 => "host unreachable",
        3 => "name lookup failed",
        4 => "refused by the host's policy",
        // The Rust server sends 5 for "disabled"; a Node gateway at 0.51.0 or earlier also sent
        // it for a timeout.
        5 => "the host's gateway is disabled, or a timeout from an older Node gateway",
        6 => "the gateway connection was closed",
        7 => "too many gateway connections",
        // A timeout is the client's own timeout error.
        8 => return WshError::Timeout,
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
            target: None,
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
