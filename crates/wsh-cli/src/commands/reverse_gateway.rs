//! The gateway connections a reverse host (`wsh reverse`, `wsh agent run`) serves: a TCP or UDP connection the operator asked
//! the host to open (`OpenTcp`, `OpenUdp`), joined to the relay's message stream.
//!
//! A TCP connection follows the rule every other host of this protocol follows (wsh #271): `GatewayClose` is a HALF-close in both
//! directions. The operator's close means "nothing more from me": it is passed on to the origin as an end of file once everything
//! the operator sent has been written, and the origin's answer is still read for as long as it takes. The origin's own end of
//! file is passed on to the operator as a plain `GatewayClose`, and what the operator sends afterwards still reaches the origin.
//! The connection is over when both sides have finished, on an error, on a discard (a `GatewayClose` with the reason
//! `"discarded"`: the sender reads nothing more, so nothing is sent back), or when it is half-closed and nothing has moved in either
//! direction for the idle bound. A UDP flow has no half-close: the operator's close ends it.
//!
//! The answering side is not watched for a peer that went away (#282): an origin that sent its whole answer and closed completely
//! looks exactly like one that half-closed and died, and the discard that watching would send makes the operator drop the part of
//! the answer it has received and not yet read.
//!
//! Reachability: `OpenTcp` / `OpenUdp` are not on the spec's relay-forwardable list, so no relay carries them to a reverse host
//! today (see test/rust/wsh-reverse-host-half-close.test.mjs); this is the behaviour the handlers have for when something does.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::warn;
use wsh_core::gateway_credit::GATEWAY_DISCARDED;
use wsh_core::messages::*;

/// Where a gateway connection sends what it has to say (the relay link; a channel in the tests).
pub trait GatewaySink: Clone + Send + Sync + 'static {
    fn send(&self, envelope: Envelope) -> impl Future<Output = ()> + Send;
}

fn data_msg(gateway_id: u32, data: Vec<u8>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayData,
        payload: Payload::GatewayData(GatewayDataPayload { gateway_id, data }),
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

/// What the runtime tells a TCP connection, in the order it arrived.
enum StreamCmd {
    Data(Vec<u8>),
    Close(Option<String>),
}

enum Tx {
    Stream(mpsc::Sender<StreamCmd>),
    Datagram(mpsc::Sender<Vec<u8>>),
}

/// One open gateway connection of a reverse host.
pub struct ReverseGatewayConnection {
    tx: Tx,
    task: tokio::task::JoinHandle<()>,
}

impl ReverseGatewayConnection {
    /// Hand the origin what the operator sent. `false`: the connection has ended and took nothing.
    pub async fn data(&self, bytes: Vec<u8>) -> bool {
        match &self.tx {
            Tx::Stream(tx) => tx.send(StreamCmd::Data(bytes)).await.is_ok(),
            Tx::Datagram(tx) => tx.send(bytes).await.is_ok(),
        }
    }

    /// The operator's `GatewayClose`. A TCP connection takes it as a half-close (or, with the reason `"discarded"`, a discard), in
    /// order after the data that went before it; a UDP flow ends.
    pub async fn close(&self, reason: Option<String>) {
        match &self.tx {
            Tx::Stream(tx) => {
                let _ = tx.send(StreamCmd::Close(reason)).await;
            }
            Tx::Datagram(_) => self.task.abort(),
        }
    }

    /// Has the connection ended (by itself)?
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// End it now, sending nothing (the session is over).
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Serve a TCP origin. `idle`: a half-closed connection with nothing moving in either direction for this long is ended.
pub fn spawn_stream<K, S>(
    sink: K,
    gateway_id: u32,
    stream: S,
    idle: Option<Duration>,
) -> ReverseGatewayConnection
where
    K: GatewaySink,
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<StreamCmd>(64);
    let task = tokio::spawn(run_stream(sink, gateway_id, stream, rx, idle));
    ReverseGatewayConnection {
        tx: Tx::Stream(tx),
        task,
    }
}

enum Event {
    /// The origin took a chunk the operator sent.
    Wrote,
    /// The operator's half-close was passed on to the origin (everything before it has been written).
    OperatorDone,
    /// The operator discarded the connection.
    Discard,
    /// Writing to the origin failed.
    WriteFailed,
}

enum End {
    /// Both sides finished by themselves.
    Finished,
    /// An error, or the idle bound: tell the operator this side reads nothing more.
    Destroyed,
    /// The operator discarded it, or the runtime let go of it: nothing is sent.
    Silent,
}

async fn run_stream<K, S>(
    sink: K,
    gateway_id: u32,
    stream: S,
    mut cmds: mpsc::Receiver<StreamCmd>,
    idle: Option<Duration>,
) where
    K: GatewaySink,
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (events_tx, mut events) = mpsc::unbounded_channel::<Event>();

    // Operator -> origin, in the order it arrived: the half-close is an end of file for the origin only after the data before it.
    let writer_task = tokio::spawn(async move {
        let mut shut = false;
        while let Some(cmd) = cmds.recv().await {
            match cmd {
                StreamCmd::Data(bytes) => {
                    if shut {
                        continue; // sent after its own close: not for the origin
                    }
                    if writer.write_all(&bytes).await.is_err() {
                        let _ = events_tx.send(Event::WriteFailed);
                        return;
                    }
                    let _ = events_tx.send(Event::Wrote);
                }
                StreamCmd::Close(reason) if reason.as_deref() == Some(GATEWAY_DISCARDED) => {
                    let _ = events_tx.send(Event::Discard);
                    return;
                }
                StreamCmd::Close(_) => {
                    if !shut {
                        shut = true;
                        let _ = writer.shutdown().await;
                        let _ = events_tx.send(Event::OperatorDone);
                    }
                }
            }
        }
    });

    // Origin -> operator, and the verdict.
    let mut buf = vec![0_u8; 16 * 1024];
    let (mut origin_done, mut operator_done) = (false, false);
    let mut last_moved = Instant::now();
    let end = loop {
        let half_closed = origin_done || operator_done;
        let deadline = idle.filter(|_| half_closed).map(|i| last_moved + i);
        tokio::select! {
            read = reader.read(&mut buf), if !origin_done => match read {
                Ok(0) => {
                    origin_done = true;
                    last_moved = Instant::now();
                    sink.send(close_msg(gateway_id, None)).await;
                    if operator_done {
                        break End::Finished;
                    }
                }
                Ok(n) => {
                    last_moved = Instant::now();
                    sink.send(data_msg(gateway_id, buf[..n].to_vec())).await;
                }
                Err(err) => {
                    warn!(gateway_id, "reverse host TCP gateway read failed: {err}");
                    break End::Destroyed;
                }
            },
            event = events.recv() => match event {
                Some(Event::Wrote) => last_moved = Instant::now(),
                Some(Event::OperatorDone) => {
                    operator_done = true;
                    last_moved = Instant::now();
                    if origin_done {
                        break End::Finished;
                    }
                }
                Some(Event::Discard) | None => break End::Silent,
                Some(Event::WriteFailed) => {
                    warn!(gateway_id, "reverse host TCP gateway write failed");
                    break End::Destroyed;
                }
            },
            _ = async { tokio::time::sleep_until(deadline.expect("guarded")).await }, if deadline.is_some() => {
                break End::Destroyed;
            }
        }
    };
    writer_task.abort();
    if matches!(end, End::Destroyed) {
        // As a destroyed connection anywhere else: a close that says nothing more will be read. Sent also after this side's own
        // close (the second close the peers define); a peer that already closed ignores it.
        sink.send(close_msg(gateway_id, Some(GATEWAY_DISCARDED)))
            .await;
    }
}

/// Serve a UDP flow (no half-close: the operator's close ends it, and so does the socket failing).
pub fn spawn_datagram<K: GatewaySink>(
    sink: K,
    gateway_id: u32,
    socket: UdpSocket,
) -> ReverseGatewayConnection {
    let socket = std::sync::Arc::new(socket);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 8192];
        loop {
            tokio::select! {
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => sink.send(data_msg(gateway_id, buf[..n].to_vec())).await,
                        Err(err) => {
                            warn!(gateway_id, "reverse host UDP gateway recv failed: {err}");
                            break;
                        }
                    }
                }
                payload = rx.recv() => {
                    match payload {
                        Some(payload) => {
                            if let Err(err) = socket.send(&payload).await {
                                warn!(gateway_id, "reverse host UDP gateway send failed: {err}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        sink.send(close_msg(
            gateway_id,
            Some("gateway datagram stream closed"),
        ))
        .await;
    });
    ReverseGatewayConnection {
        tx: Tx::Datagram(tx),
        task,
    }
}

#[cfg(test)]
mod tests {
    //! The half-close rule of a reverse host's TCP connection, against an in-memory origin. The origin's end of the stream is `far`;
    //! what the host sends the operator arrives on `rx`. Time is paused where an idle bound is tested, so nothing waits on a clock.

    use super::*;
    use tokio::io::{duplex, DuplexStream};

    #[derive(Clone)]
    struct ChanSink(mpsc::UnboundedSender<Envelope>);

    impl GatewaySink for ChanSink {
        async fn send(&self, envelope: Envelope) {
            let _ = self.0.send(envelope);
        }
    }

    #[derive(Debug, PartialEq)]
    enum Seen {
        Data(Vec<u8>),
        Close(Option<String>),
    }

    fn seen(envelope: Envelope) -> Seen {
        match envelope.payload {
            Payload::GatewayData(d) => Seen::Data(d.data),
            Payload::GatewayClose(c) => Seen::Close(c.reason),
            other => panic!("unexpected message {other:?}"),
        }
    }

    /// A connection to an in-memory origin; `idle` as `spawn_stream`.
    fn connect(
        idle: Option<Duration>,
    ) -> (
        ReverseGatewayConnection,
        DuplexStream,
        mpsc::UnboundedReceiver<Envelope>,
    ) {
        let (host_end, far) = duplex(1 << 20);
        let (tx, rx) = mpsc::unbounded_channel();
        (spawn_stream(ChanSink(tx), 7, host_end, idle), far, rx)
    }

    async fn next(rx: &mut mpsc::UnboundedReceiver<Envelope>) -> Seen {
        seen(
            rx.recv()
                .await
                .expect("the connection ended without saying so"),
        )
    }

    /// Everything the host sends until the channel is closed (the connection has ended and dropped its sink).
    async fn everything(mut rx: mpsc::UnboundedReceiver<Envelope>) -> Vec<Seen> {
        let mut all = Vec::new();
        while let Some(e) = rx.recv().await {
            all.push(seen(e));
        }
        all
    }

    fn data_of(all: &[Seen]) -> Vec<u8> {
        all.iter()
            .filter_map(|s| match s {
                Seen::Data(d) => Some(d.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[tokio::test]
    async fn an_operator_that_finished_sending_still_gets_the_answer() {
        let (conn, mut far, rx) = connect(None);
        // The origin answers only once it has read the whole request, up to its end of file.
        let origin = tokio::spawn(async move {
            let mut request = Vec::new();
            far.read_to_end(&mut request).await.unwrap();
            far.write_all(b"answer to ").await.unwrap();
            far.write_all(&request).await.unwrap();
            far.shutdown().await.unwrap();
        });
        assert!(conn.data(b"the request".to_vec()).await);
        conn.close(None).await;
        conn.task.await.unwrap();
        origin.await.unwrap();
        let all = everything(rx).await;
        assert_eq!(data_of(&all), b"answer to the request");
        assert_eq!(
            all.last(),
            Some(&Seen::Close(None)),
            "a plain half-close, not a discard"
        );
    }

    #[tokio::test]
    async fn what_the_operator_sent_before_its_close_is_written_whole_before_the_origin_sees_the_end(
    ) {
        let (conn, mut far, _rx) = connect(None);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            far.read_to_end(&mut got).await.unwrap();
            got
        });
        let chunk = vec![9_u8; 16_000];
        for _ in 0..40 {
            assert!(conn.data(chunk.clone()).await);
        }
        conn.close(None).await; // queued behind 640 kB that is still being written
        assert_eq!(reader.await.unwrap().len(), 40 * 16_000);
    }

    #[tokio::test]
    async fn an_origin_that_finishes_first_is_passed_on_and_what_follows_still_reaches_it() {
        let (conn, mut far, mut rx) = connect(None);
        far.write_all(b"all from me").await.unwrap();
        // Only the origin's write side ends: `DuplexStream` has no half-close of its own, so end it by shutting down.
        far.shutdown().await.unwrap();
        assert_eq!(next(&mut rx).await, Seen::Data(b"all from me".to_vec()));
        assert_eq!(next(&mut rx).await, Seen::Close(None));
        assert!(!conn.is_finished(), "held for the operator's side");
        assert!(conn.data(b"late words".to_vec()).await);
        let mut got = [0_u8; 10];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"late words");
        conn.close(None).await;
        conn.task.await.unwrap();
        assert!(
            everything(rx).await.is_empty(),
            "nothing more is said once both have finished"
        );
    }

    #[tokio::test]
    async fn a_discard_from_the_operator_ends_it_and_nothing_is_sent_back() {
        let (conn, mut far, rx) = connect(None);
        assert!(conn.data(b"abc".to_vec()).await);
        conn.close(Some("discarded".into())).await;
        conn.task.await.unwrap();
        let mut rest = Vec::new();
        let _ = far.read_to_end(&mut rest).await; // the origin's socket is gone
        assert!(everything(rx).await.is_empty());
    }

    #[tokio::test]
    async fn a_second_close_discarded_after_a_half_close_ends_a_connection_the_origin_holds_open() {
        let (conn, far, rx) = connect(None);
        conn.close(None).await;
        // Held: the origin has said nothing and has not closed.
        let mut far = far;
        let mut one = [0_u8; 1];
        assert_eq!(
            far.read(&mut one).await.unwrap(),
            0,
            "the origin saw the half-close as an end of file"
        );
        assert!(!conn.is_finished());
        conn.close(Some("discarded".into())).await;
        conn.task.await.unwrap();
        assert!(everything(rx).await.is_empty());
    }

    #[tokio::test]
    async fn an_origin_that_sent_everything_and_closed_completely_is_not_discarded() {
        let (conn, mut far, mut rx) = connect(None);
        let body = vec![3_u8; 300_000];
        far.write_all(&body).await.unwrap();
        drop(far); // gone entirely, as an HTTP/1.0 server is after its response
        let mut got = Vec::new();
        loop {
            match next(&mut rx).await {
                Seen::Data(d) => got.extend(d),
                Seen::Close(reason) => {
                    assert_eq!(reason, None, "the end of a response is not a discard");
                    break;
                }
            }
        }
        assert_eq!(got, body);
        assert!(
            !conn.is_finished(),
            "the operator may still be reading; it ends the connection"
        );
        conn.close(None).await;
        conn.task.await.unwrap();
        assert!(everything(rx).await.is_empty());
    }

    #[tokio::test]
    async fn a_write_to_an_origin_that_is_gone_ends_the_connection_with_a_discard() {
        let (conn, far, mut rx) = connect(None);
        drop(far);
        assert_eq!(next(&mut rx).await, Seen::Close(None)); // its end of file
                                                            // The operator keeps sending to it: that fails, and the connection is destroyed.
        let _ = conn.data(b"x".to_vec()).await;
        assert_eq!(next(&mut rx).await, Seen::Close(Some("discarded".into())));
        conn.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_closed_connection_with_nothing_moving_is_ended_by_the_idle_bound() {
        let idle = Duration::from_secs(10);
        let (conn, _far, mut rx) = connect(Some(idle));
        let t0 = Instant::now();
        conn.close(None).await;
        assert_eq!(next(&mut rx).await, Seen::Close(Some("discarded".into())));
        assert!(Instant::now() - t0 >= idle, "not before the bound");
        conn.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_is_not_half_closed_has_no_idle_bound() {
        let (conn, _far, mut rx) = connect(Some(Duration::from_secs(10)));
        tokio::time::sleep(Duration::from_secs(100_000)).await;
        assert!(!conn.is_finished());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_keeps_arriving_keeps_a_half_closed_connection_open() {
        let idle = Duration::from_secs(10);
        let (conn, mut far, mut rx) = connect(Some(idle));
        conn.close(None).await;
        // A byte every six seconds for a minute: far past the bound, never quiet for all of it.
        let slow_origin = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_secs(6)).await;
                far.write_all(b".").await.unwrap();
            }
            far // kept open, now quiet
        });
        for _ in 0..10 {
            assert_eq!(next(&mut rx).await, Seen::Data(b".".to_vec()));
        }
        let quiet_from = Instant::now();
        let _far = slow_origin.await.unwrap();
        assert_eq!(next(&mut rx).await, Seen::Close(Some("discarded".into())));
        assert!(Instant::now() - quiet_from >= idle);
        conn.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn what_the_operator_keeps_sending_keeps_a_half_closed_connection_open_too() {
        let idle = Duration::from_secs(10);
        let (conn, mut far, mut rx) = connect(Some(idle));
        // The origin finished (half-closed); the operator goes on sending, a chunk every six seconds.
        far.shutdown().await.unwrap();
        assert_eq!(next(&mut rx).await, Seen::Close(None));
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(6)).await;
            assert!(conn.data(b"x".to_vec()).await);
        }
        assert!(
            !conn.is_finished(),
            "sixty seconds of it, and never ten quiet ones"
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(next(&mut rx).await, Seen::Close(Some("discarded".into())));
    }
}
