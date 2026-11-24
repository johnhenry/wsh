//! Typed rpc channels (wsh #85) from the client side: `Open { kind: "rpc", command: <protocol> }`,
//! answered `OpenOk` with `data_mode: stream`, after which the client opens one QMux data stream whose
//! payload, in both directions, is a CBOR sequence (RFC 8742) of JSON-RPC 2.0 messages. This is the
//! Rust twin of `WshClient.openRpc` / `RpcChannel` in `src/client.mjs` and `src/rpc.mjs`, and speaks
//! to the hosts that serve them (`createWshServer({ rpc })`, `createMemoryHost({ rpc })`, `wsh-server`).
//!
//! Where the host has no client-opened data streams (a sealed session, a host behind a relay) it states
//! `rpc-virtual` instead of `rpc` (wsh #191), answers `OpenOk` with `data_mode: virtual`, and the same CBOR
//! sequence rides `SessionData` (inside the session's seal, if it has one), metered by `GatewayCredit`
//! (`gateway_id = 0x80000000 | channel_id`, 256 KiB per direction, returned in bytes as [`RpcChannel::recv`]
//! takes messages in). The channel is chosen from what the host advertises; callers change nothing.
//!
//! The channel is deliberately thin: it moves JSON-RPC messages (`serde_json::Value`) and enforces the
//! host's `rpc-max-message:<n>` bound in both directions; it does not correlate requests (the caller
//! owns ids) or interpret `$/cancel` / `$/progress`, because the user of an `mcp` channel
//! (`wsh mcp`) passes MCP messages through verbatim.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot, Mutex};
use wsh_core::error::{WshError, WshResult};
use wsh_core::rpc_codec::{encode_message, CborSequenceDecoder};
use wsh_core::rpc_credit::CreditLink;
use wsh_core::transport::ByteStream;

use crate::session::{ControlAction, WshSession};

pub use wsh_core::rpc_credit::RPC_VIRTUAL_FEATURE;

/// `ServerHello` feature: the host serves `rpc` channels.
pub const RPC_FEATURE: &str = "rpc";
/// `ServerHello` feature prefix: one `rpc-protocol:<name>` per protocol the host serves.
pub const RPC_PROTOCOL_PREFIX: &str = "rpc-protocol:";
/// `ServerHello` feature prefix: `rpc-max-message:<bytes>`, the largest single message the host accepts.
pub const RPC_MAX_MESSAGE_PREFIX: &str = "rpc-max-message:";
/// Largest message when the host does not say (1 MiB).
pub const RPC_DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;

/// What a host's `ServerHello.features` say about rpc.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcOffer {
    /// The host lists `rpc`: its channels ride client-opened data streams.
    pub enabled: bool,
    /// The host lists `rpc-virtual` (and not `rpc`, on a connection that has no data streams): its channels
    /// ride the control plane, metered by credit (wsh #191).
    pub virtual_data: bool,
    /// The protocols it serves (`mcp`, `wsh-host`, `wsh-fs`, an embedder's own), in advertised order.
    pub protocols: Vec<String>,
    /// The largest single message it accepts and will send.
    pub max_message_bytes: usize,
}

impl RpcOffer {
    pub fn parse(features: &[String]) -> Self {
        let mut offer = RpcOffer {
            enabled: false,
            virtual_data: false,
            protocols: Vec::new(),
            max_message_bytes: RPC_DEFAULT_MAX_MESSAGE,
        };
        for f in features {
            if f == RPC_FEATURE {
                offer.enabled = true;
            } else if f == RPC_VIRTUAL_FEATURE {
                offer.virtual_data = true;
            } else if let Some(name) = f.strip_prefix(RPC_PROTOCOL_PREFIX) {
                offer.protocols.push(name.to_string());
            } else if let Some(n) = f.strip_prefix(RPC_MAX_MESSAGE_PREFIX) {
                if let Ok(n) = n.parse::<usize>() {
                    if n > 0 {
                        offer.max_message_bytes = n;
                    }
                }
            }
        }
        offer
    }

    /// The host offers rpc channels in either form.
    pub fn offered(&self) -> bool {
        self.enabled || self.virtual_data
    }

    /// The channels ride the control plane: the host states `rpc-virtual` and not `rpc`. (A host that states both
    /// is read as stream mode, as the JS client does.)
    pub fn is_virtual(&self) -> bool {
        self.virtual_data && !self.enabled
    }

    /// Whether the host serves `protocol`.
    pub fn serves(&self, protocol: &str) -> bool {
        self.offered() && self.protocols.iter().any(|p| p == protocol)
    }
}

/// A protocol name travels in a feature string and in `Open.command`: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
pub fn valid_protocol_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

enum Command {
    Write(Vec<u8>, oneshot::Sender<WshResult<()>>),
    Close,
}

/// A received message and the bytes of it the host's credit is still to be returned for (virtual mode).
type Item = (WshResult<Value>, usize);

enum Incoming {
    Bounded(mpsc::Receiver<Item>),
    Unbounded(mpsc::UnboundedReceiver<Item>),
}

impl Incoming {
    async fn recv(&mut self) -> Option<Item> {
        match self {
            Incoming::Bounded(rx) => rx.recv().await,
            Incoming::Unbounded(rx) => rx.recv().await,
        }
    }
}

/// How an open channel writes.
enum Writer {
    /// A data stream, owned by the pump task.
    Stream(mpsc::Sender<Command>),
    /// The control plane, metered by credit. One message is written at a time (its chunks stay together).
    Virtual {
        link: Arc<CreditLink>,
        inbound: Arc<VirtualInbound>,
        write_lock: Mutex<()>,
    },
}

/// The receiving end of a virtual-mode channel: what the dispatch loop feeds. Not blocking, and bounded by credit: the
/// host may send no more than the credit it was given, and credit comes back only as messages are read.
pub(crate) struct VirtualInbound {
    link: Arc<CreditLink>,
    inner: std::sync::Mutex<Inbound>,
    tx: std::sync::Mutex<Option<mpsc::UnboundedSender<Item>>>,
    closed: Arc<AtomicBool>,
    channel_id: u32,
    control: mpsc::Sender<ControlAction>,
    /// Hands the host `n` bytes of credit back (a `GatewayCredit`).
    send_credit: Box<dyn Fn(u64) + Send + Sync>,
}

/// What the receiving end owes the host credit for. A reader that does not read must bound the host, and a message
/// larger than the credit window must still arrive, so:
///  - the bytes of a complete message are returned when the message is read;
///  - the bytes of a message still being assembled are returned at once while nothing complete is waiting to be read
///    (the decoder bounds them by the message limit), and held back while something is, until the queue drains.
struct Inbound {
    decoder: CborSequenceDecoder,
    /// Complete messages not yet read.
    queued: usize,
    /// Bytes of the incomplete message already returned as credit, and bytes of it still held back.
    credited: usize,
    held: usize,
}

impl VirtualInbound {
    /// `SessionData` arrived for the channel.
    pub(crate) fn on_data(&self, bytes: &[u8]) {
        if bytes.is_empty() || self.closed.load(Ordering::Relaxed) {
            return;
        }
        if !self.link.receive(bytes.len()) {
            self.fail("the host sent more rpc data than the credit it was given".into());
            return;
        }
        let mut give = 0usize;
        {
            let mut s = self.inner.lock().expect("rpc inbound lock");
            let before = s.decoder.pending();
            let messages = match s.decoder.feed(bytes) {
                Ok(m) => m,
                Err(e) => {
                    drop(s);
                    self.fail(format!("rpc stream: {e}"));
                    return;
                }
            };
            let after = s.decoder.pending();
            if messages.is_empty() {
                // Still assembling: the new bytes are returned now if the reader has nothing unread, held otherwise.
                s.held += after - before;
                if s.queued == 0 {
                    give = s.held;
                    s.credited += s.held;
                    s.held = 0;
                }
            } else {
                // The complete messages' bytes (including those of the message that was being assembled) are owed when
                // they are read, less what was already returned for that message; what is left over starts the next one.
                let batch = before + bytes.len() - after;
                let owed = batch - s.credited;
                s.credited = 0;
                s.held = after;
                let count = messages.len();
                s.queued += count;
                let tx = self.tx.lock().expect("rpc incoming lock");
                for (i, message) in messages.into_iter().enumerate() {
                    if let Some(tx) = tx.as_ref() {
                        let _ = tx.send((Ok(message), if i + 1 == count { owed } else { 0 }));
                    }
                }
            }
        }
        self.consumed(give);
    }

    /// The reader took a message (with the bytes it still owes credit for) out of the queue.
    fn after_recv(&self, owed: usize) {
        let mut give = owed;
        {
            let mut s = self.inner.lock().expect("rpc inbound lock");
            s.queued = s.queued.saturating_sub(1);
            if s.queued == 0 && s.held > 0 {
                give += s.held;
                s.credited += s.held;
                s.held = 0;
            }
        }
        self.consumed(give);
    }

    fn consumed(&self, n: usize) {
        if n == 0 {
            return;
        }
        if let Some(give) = self.link.consumed(n) {
            (self.send_credit)(give);
        }
    }

    /// The channel is over (the host closed it, the connection dropped, or this end did).
    pub(crate) fn on_close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.link.close();
        self.tx.lock().expect("rpc incoming lock").take();
    }

    /// The host broke the protocol: the reader is told once, last; the host is told the channel is closed.
    fn fail(&self, why: String) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        self.link.close();
        if let Some(tx) = self.tx.lock().expect("rpc incoming lock").take() {
            let _ = tx.send((Err(WshError::Other(why)), 0));
        }
        let _ = self.control.try_send(ControlAction::Close {
            channel_id: self.channel_id,
        });
    }

    /// A `GatewayCredit` arrived for the channel.
    pub(crate) fn on_credit(&self, bytes: u32) {
        self.link.grant(u64::from(bytes));
    }
}

/// An open rpc channel: JSON-RPC messages out with [`send`](Self::send), in with [`recv`](Self::recv).
pub struct RpcChannel {
    writer: Writer,
    incoming: Mutex<Incoming>,
    max_message_bytes: usize,
    closed: Arc<AtomicBool>,
    /// Stands for the channel in the client's session table, so the host's `Close` finds it.
    stub: Arc<WshSession>,
}

impl RpcChannel {
    pub(crate) fn start(
        stream: Box<dyn ByteStream>,
        max_message_bytes: usize,
        stub: Arc<WshSession>,
    ) -> Self {
        let (commands, command_rx) = mpsc::channel(64);
        let (incoming_tx, incoming) = mpsc::channel(256);
        let closed = Arc::new(AtomicBool::new(false));
        tokio::spawn(pump(
            stream,
            command_rx,
            incoming_tx,
            max_message_bytes,
            closed.clone(),
        ));
        Self {
            writer: Writer::Stream(commands),
            incoming: Mutex::new(Incoming::Bounded(incoming)),
            max_message_bytes,
            closed,
            stub,
        }
    }

    /// A channel in virtual data mode (wsh #191): `stub` is the channel's entry in the client's session table, which
    /// forwards `SessionData` and `GatewayCredit` to the returned channel; `send_credit` writes a `GatewayCredit`.
    pub(crate) fn start_virtual(
        max_message_bytes: usize,
        stub: Arc<WshSession>,
        control: mpsc::Sender<ControlAction>,
        send_credit: Box<dyn Fn(u64) + Send + Sync>,
    ) -> Self {
        let link = Arc::new(CreditLink::new());
        let (tx, rx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        let inbound = Arc::new(VirtualInbound {
            link: link.clone(),
            inner: std::sync::Mutex::new(Inbound {
                decoder: CborSequenceDecoder::new(max_message_bytes),
                queued: 0,
                credited: 0,
                held: 0,
            }),
            tx: std::sync::Mutex::new(Some(tx)),
            closed: closed.clone(),
            channel_id: stub.channel_id(),
            control,
            send_credit,
        });
        stub.set_rpc_inbound(inbound.clone());
        Self {
            writer: Writer::Virtual {
                link,
                inbound,
                write_lock: Mutex::new(()),
            },
            incoming: Mutex::new(Incoming::Unbounded(rx)),
            max_message_bytes,
            closed,
            stub,
        }
    }

    /// The largest single message either side may send on this channel.
    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Whether the channel has ended (the host closed it, the connection dropped, or [`close`](Self::close)).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Send one JSON-RPC message. A message over the host's bound is refused here, before anything
    /// is written (the host would close the channel on it).
    pub async fn send(&self, message: &Value) -> WshResult<()> {
        let bytes = encode_message(message).map_err(|e| WshError::Other(e.to_string()))?;
        if bytes.len() > self.max_message_bytes {
            return Err(WshError::Other(format!(
                "message of {} bytes exceeds the {} byte rpc message limit",
                bytes.len(),
                self.max_message_bytes
            )));
        }
        let closed = || WshError::Channel("rpc channel is closed".into());
        match &self.writer {
            Writer::Stream(commands) => {
                let (ack, done) = oneshot::channel();
                commands
                    .send(Command::Write(bytes, ack))
                    .await
                    .map_err(|_| closed())?;
                done.await.map_err(|_| closed())?
            }
            Writer::Virtual {
                link, write_lock, ..
            } => {
                // The chunks of one message stay together: another sender waits its turn.
                let _turn = write_lock.lock().await;
                let mut rest = &bytes[..];
                while !rest.is_empty() {
                    let n = link.reserve(rest.len()).await.map_err(|_| closed())?;
                    self.stub.write(&rest[..n]).await?;
                    rest = &rest[n..];
                }
                Ok(())
            }
        }
    }

    /// The next message from the host. `None` once the channel has ended and everything it sent has
    /// been read; `Some(Err(..))` once, last, when the stream could not be decoded or failed (or, on a
    /// channel in virtual data mode, when the host sent more than the credit it was given).
    pub async fn recv(&self) -> Option<WshResult<Value>> {
        let (message, owed) = self.incoming.lock().await.recv().await?;
        // Taking a message in is what hands the host credit for its bytes back.
        if let (Writer::Virtual { inbound, .. }, Ok(_)) = (&self.writer, &message) {
            inbound.after_recv(owed);
        }
        Some(message)
    }

    /// Close the channel: the host is told (`Close`) and the data stream finished.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        match &self.writer {
            Writer::Stream(commands) => {
                let _ = commands.send(Command::Close).await;
            }
            Writer::Virtual { inbound, .. } => inbound.on_close(),
        }
        let _ = self.stub.close().await;
    }
}

impl Drop for RpcChannel {
    fn drop(&mut self) {
        let was_closed = self.closed.swap(true, Ordering::Relaxed);
        match &self.writer {
            Writer::Stream(commands) => {
                let _ = commands.try_send(Command::Close);
            }
            Writer::Virtual { inbound, .. } => {
                if !was_closed {
                    // Dropped without `close()`: the host is still told.
                    let _ = inbound.control.try_send(ControlAction::Close {
                        channel_id: inbound.channel_id,
                    });
                }
                inbound.on_close();
            }
        }
    }
}

/// Owns the stream: writes what `send` queues and decodes what arrives, in one task so a read that is
/// waiting never holds the stream against a write (`read` is cancel-safe on every stream this client has).
async fn pump(
    mut stream: Box<dyn ByteStream>,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<Item>,
    max_message_bytes: usize,
    closed: Arc<AtomicBool>,
) {
    let mut decoder = CborSequenceDecoder::new(max_message_bytes);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => match command {
                Some(Command::Write(bytes, ack)) => {
                    let result = stream.write_all(&bytes).await;
                    let failed = result.is_err();
                    let _ = ack.send(result);
                    if failed {
                        break;
                    }
                }
                Some(Command::Close) | None => {
                    let _ = stream.close().await;
                    break;
                }
            },
            read = stream.read(&mut buf) => match read {
                Ok(0) => break,
                Ok(n) => match decoder.feed(&buf[..n]) {
                    Ok(messages) => {
                        for message in messages {
                            if incoming.send((Ok(message), 0)).await.is_err() {
                                closed.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = incoming.send((Err(WshError::Other(format!("rpc stream: {e}"))), 0)).await;
                        let _ = stream.close().await;
                        break;
                    }
                },
                Err(e) => {
                    let _ = incoming.send((Err(e), 0)).await;
                    break;
                }
            },
        }
    }
    closed.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_offer_reads_protocols_and_the_bound() {
        let o = RpcOffer::parse(&features(&[
            "mcp-call-id",
            "rpc",
            "rpc-protocol:wsh-host",
            "rpc-protocol:mcp",
            "rpc-max-message:4096",
        ]));
        assert!(o.enabled);
        assert_eq!(o.protocols, vec!["wsh-host", "mcp"]);
        assert_eq!(o.max_message_bytes, 4096);
        assert!(o.serves("mcp") && !o.serves("wsh-fs"));
    }

    #[test]
    fn a_host_without_rpc_serves_nothing_even_if_a_protocol_is_listed() {
        let o = RpcOffer::parse(&features(&["rpc-protocol:mcp"]));
        assert!(!o.enabled && !o.serves("mcp"));
        assert_eq!(o.max_message_bytes, RPC_DEFAULT_MAX_MESSAGE);
    }

    #[test]
    fn a_nonsense_bound_is_ignored() {
        for bad in [
            "rpc-max-message:0",
            "rpc-max-message:-1",
            "rpc-max-message:x",
        ] {
            assert_eq!(
                RpcOffer::parse(&features(&["rpc", bad])).max_message_bytes,
                RPC_DEFAULT_MAX_MESSAGE
            );
        }
    }

    #[test]
    fn protocol_names_are_boring() {
        assert!(
            valid_protocol_name("mcp")
                && valid_protocol_name("wsh-fs")
                && valid_protocol_name("a.b_c-1")
        );
        for bad in ["", "-x", ".x", "a b", "a/b", "a\0", &"x".repeat(65)] {
            assert!(!valid_protocol_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn rpc_virtual_is_its_own_form_and_rpc_wins_when_both_are_stated() {
        let v = RpcOffer::parse(&features(&[
            "rpc-virtual",
            "rpc-protocol:mcp",
            "rpc-max-message:4096",
        ]));
        assert!(!v.enabled && v.virtual_data && v.offered() && v.is_virtual());
        assert!(v.serves("mcp") && !v.serves("wsh-fs"));
        assert_eq!(v.max_message_bytes, 4096);
        let both = RpcOffer::parse(&features(&["rpc", "rpc-virtual", "rpc-protocol:mcp"]));
        assert!(
            both.offered() && !both.is_virtual(),
            "stream mode, as the JS client reads it"
        );
        let none = RpcOffer::parse(&features(&["rpc-protocol:mcp"]));
        assert!(!none.offered() && !none.serves("mcp"));
    }

    // ── virtual data mode (wsh #191) ──────────────────────────────────────

    use std::sync::atomic::AtomicU64;
    use wsh_core::messages::ChannelKind;
    use wsh_core::rpc_credit::{RPC_CREDIT_WINDOW, RPC_VIRTUAL_CHUNK_BYTES};

    struct Rig {
        channel: Arc<RpcChannel>,
        inbound: Arc<VirtualInbound>,
        actions: mpsc::Receiver<ControlAction>,
        credit_sent: Arc<AtomicU64>,
    }

    fn rig(max_message_bytes: usize) -> Rig {
        let (control_tx, actions) = mpsc::channel(4096);
        let stub = Arc::new(WshSession::new_virtual(
            7,
            ChannelKind::Rpc,
            control_tx.clone(),
            Vec::new(),
        ));
        let credit_sent = Arc::new(AtomicU64::new(0));
        let counter = credit_sent.clone();
        let channel = RpcChannel::start_virtual(
            max_message_bytes,
            stub,
            control_tx,
            Box::new(move |n| {
                counter.fetch_add(n, Ordering::SeqCst);
            }),
        );
        let inbound = match &channel.writer {
            Writer::Virtual { inbound, .. } => inbound.clone(),
            Writer::Stream(_) => unreachable!(),
        };
        Rig {
            channel: Arc::new(channel),
            inbound,
            actions,
            credit_sent,
        }
    }

    /// A string message of about `n` bytes on the wire.
    fn message_of(n: usize) -> Value {
        serde_json::json!({ "jsonrpc": "2.0", "method": "x", "params": { "pad": "p".repeat(n) } })
    }

    #[tokio::test]
    async fn a_virtual_channel_sends_session_data_in_chunks_and_stops_at_its_credit() {
        let mut r = rig(4 * 1024 * 1024);
        let big = message_of(600 * 1024);
        let sender = {
            let c = r.channel.clone();
            tokio::spawn(async move { c.send(&big).await })
        };
        // one window goes out, in chunks, and then the writer waits
        let mut sent = 0usize;
        while sent < RPC_CREDIT_WINDOW {
            match r.actions.recv().await.unwrap() {
                ControlAction::Data { channel_id, data } => {
                    assert_eq!(channel_id, 7);
                    assert!(data.len() <= RPC_VIRTUAL_CHUNK_BYTES);
                    sent += data.len();
                }
                _ => panic!("only SessionData is written"),
            }
        }
        assert_eq!(sent, RPC_CREDIT_WINDOW);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            r.actions.try_recv().is_err(),
            "no credit: nothing more is sent"
        );
        assert!(!sender.is_finished());
        // credit arrives; the rest follows and the send completes
        r.inbound.on_credit(RPC_CREDIT_WINDOW as u32);
        r.inbound.on_credit(RPC_CREDIT_WINDOW as u32);
        sender.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_slow_reader_holds_back_the_hosts_credit_and_reading_returns_it() {
        let r = rig(1024 * 1024);
        // 4 messages of ~60 KiB arrive and nobody reads them
        let wire = encode_message(&message_of(60 * 1024)).unwrap();
        for _ in 0..4 {
            r.inbound.on_data(&wire);
        }
        assert_eq!(
            r.credit_sent.load(Ordering::SeqCst),
            0,
            "unread data returns no credit: the host runs out and waits"
        );
        // reading takes the bytes in, and half a window is handed back
        for _ in 0..4 {
            assert!(r.channel.recv().await.unwrap().is_ok());
        }
        // (in batches of half a window: the last message's bytes may still be owed)
        let returned = r.credit_sent.load(Ordering::SeqCst);
        assert!(
            returned >= (RPC_CREDIT_WINDOW / 2) as u64 && returned <= 4 * wire.len() as u64,
            "{returned}"
        );
    }

    /// A host that sends 100 KiB messages in 10 KiB chunks, only while it holds credit. Without a reader it stops after
    /// about one window plus a message or two, however long it is left; once the reader reads, every message arrives.
    #[tokio::test]
    async fn a_reader_that_does_not_read_bounds_a_host_sending_chunked_messages() {
        let r = rig(1024 * 1024);
        let wire = encode_message(&message_of(100 * 1024)).unwrap();
        let total_messages = 20usize;
        let stream: Vec<u8> = (0..total_messages).flat_map(|_| wire.clone()).collect();
        let mut host_credit = RPC_CREDIT_WINDOW as u64;
        let mut sent = 0usize;
        let mut credited_seen = 0u64;
        let pump = |sent: &mut usize, host_credit: &mut u64, credited_seen: &mut u64| {
            // credit the application handed back since the last look
            let now = r.credit_sent.load(Ordering::SeqCst);
            *host_credit += now - *credited_seen;
            *credited_seen = now;
            while *sent < stream.len() {
                let n = (stream.len() - *sent).min(10 * 1024);
                if (n as u64) > *host_credit {
                    return;
                }
                *host_credit -= n as u64;
                r.inbound.on_data(&stream[*sent..*sent + n]);
                *sent += n;
            }
        };
        pump(&mut sent, &mut host_credit, &mut credited_seen);
        pump(&mut sent, &mut host_credit, &mut credited_seen);
        assert!(
            sent + 10 * 1024 > RPC_CREDIT_WINDOW && sent <= RPC_CREDIT_WINDOW + 3 * wire.len(),
            "unread, the host got to send {sent} bytes against a {RPC_CREDIT_WINDOW} byte window"
        );
        // reading releases it: all of them arrive, in order, with no deadlock
        let mut got = 0;
        while got < total_messages {
            while sent < stream.len() {
                let before = sent;
                pump(&mut sent, &mut host_credit, &mut credited_seen);
                if sent == before {
                    break;
                }
            }
            let m = tokio::time::timeout(std::time::Duration::from_secs(5), r.channel.recv())
                .await
                .expect("the reader and the host deadlocked")
                .unwrap()
                .unwrap();
            assert_eq!(m["params"]["pad"].as_str().unwrap().len(), 100 * 1024);
            got += 1;
        }
    }

    #[tokio::test]
    async fn a_host_that_overruns_its_credit_has_the_channel_closed() {
        let mut r = rig(1024 * 1024);
        let wire = encode_message(&message_of(60 * 1024)).unwrap();
        // the window is 262144 bytes: 5 messages of ~61 KiB are over it
        for _ in 0..5 {
            r.inbound.on_data(&wire);
        }
        let mut got = Vec::new();
        while let Some(m) = r.channel.recv().await {
            got.push(m);
        }
        assert_eq!(got.iter().filter(|m| m.is_ok()).count(), 4);
        let last = got.last().unwrap();
        assert!(
            matches!(last, Err(e) if e.to_string().contains("more rpc data than the credit")),
            "{last:?}"
        );
        assert!(r.channel.is_closed());
        // the host is told, and nothing can be written
        let mut told = false;
        while let Ok(a) = r.actions.try_recv() {
            told |= matches!(a, ControlAction::Close { channel_id: 7 });
        }
        assert!(told);
        assert!(r.channel.send(&message_of(10)).await.is_err());
    }

    #[tokio::test]
    async fn a_message_over_the_bound_is_refused_before_it_is_assembled() {
        let r = rig(1024);
        // the header of a 1 MiB text string: refused on the header alone
        r.inbound.on_data(&[0x7a, 0x00, 0x10, 0x00, 0x00]);
        let first = r.channel.recv().await.unwrap();
        assert!(
            matches!(&first, Err(e) if e.to_string().contains("exceeds the 1024 byte rpc message limit")),
            "{first:?}"
        );
        assert!(r.channel.recv().await.is_none());
    }

    #[tokio::test]
    async fn a_message_larger_than_the_window_still_arrives() {
        let r = rig(4 * 1024 * 1024);
        let wire = encode_message(&message_of(600 * 1024)).unwrap();
        let reader = {
            let c = r.channel.clone();
            tokio::spawn(async move { c.recv().await })
        };
        // the host sends within its credit, and as the partial message is taken in the credit comes back
        let mut off = 0;
        while off < wire.len() {
            let n = (wire.len() - off).min(32 * 1024);
            r.inbound.on_data(&wire[off..off + n]);
            off += n;
        }
        let got = reader.await.unwrap().unwrap().unwrap();
        assert_eq!(got["params"]["pad"].as_str().unwrap().len(), 600 * 1024);
        assert!(r.credit_sent.load(Ordering::SeqCst) >= (wire.len() as u64) / 2);
    }

    #[tokio::test]
    async fn the_host_closing_ends_the_channel_and_releases_a_waiting_writer() {
        let r = rig(4 * 1024 * 1024);
        let sender = {
            let c = r.channel.clone();
            let big = message_of(600 * 1024);
            tokio::spawn(async move { c.send(&big).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        r.inbound.on_close();
        assert!(sender.await.unwrap().is_err());
        assert!(r.channel.recv().await.is_none());
    }
}
