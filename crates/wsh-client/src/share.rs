//! Operator-side shared folders, the protocol half (#159): this client OFFERS named directories
//! (`ShareOffer`) and answers the host's file requests (`ShareRequest` -> `ShareReply`).
//!
//! This module knows nothing about files. It owns the wire rules every provider gets for free:
//!
//! - nothing is served until a provider has been installed AND offered (a host cannot make the
//!   client serve what was never offered: an unsolicited request is refused);
//! - at most `max_inflight` requests run at once, the number the offer promised the host; more
//!   are answered `EAGAIN` at once, never queued, so a flood costs one small reply each;
//! - a reply is not queued while the connection's outgoing queue is already deep, so a host that
//!   stops reading cannot make the client buffer more than a few reply-sized frames;
//! - when the connection ends the provider is told, to drop its open handles.
//!
//! The file system side (confinement, handles, limits) is a [`ShareProvider`]: the CLI's
//! `sharefs` implements it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use wsh_core::messages::*;
use wsh_core::{frame_encode, WshError, WshResult};

/// Feature a host lists when it can use shares (`ServerHello.features`).
pub const SHARES_FEATURE: &str = "shares";
/// Most shares one offer may name.
pub const MAX_SHARES: usize = 16;
/// Free slots the outgoing queue must have before a reply is queued (of 256): a deep queue means
/// the host is not reading, and each reply may carry `max_bytes`.
const OUT_RESERVE: usize = 192;

/// Answers the host's file requests. `serve` must never panic and must always produce a reply.
pub trait ShareProvider: Send + Sync + 'static {
    fn serve<'a>(
        &'a self,
        request: ShareRequestPayload,
    ) -> Pin<Box<dyn Future<Output = ShareReplyPayload> + Send + 'a>>;

    /// The connection ended: close every open handle.
    fn shutdown(&self) {}
}

/// The error reply a hub makes itself.
pub fn error_reply(request_id: u32, errno: &str, message: &str) -> ShareReplyPayload {
    ShareReplyPayload {
        request_id,
        ok: false,
        errno: Some(errno.to_string()),
        message: Some(message.to_string()),
        attr: serde_json::Value::Null,
        entries: serde_json::Value::Null,
        cursor: None,
        handle: None,
        data: None,
        eof: None,
        written: None,
        target: None,
    }
}

struct Active {
    provider: Arc<dyn ShareProvider>,
    permits: Arc<Semaphore>,
}

/// The per-connection state; held by the client's gateway hub (which already carries the
/// connection's outgoing sender and is told when the connection ends).
pub(crate) struct ShareHub {
    out: mpsc::Sender<Vec<u8>>,
    active: Mutex<Option<Active>>,
}

impl ShareHub {
    pub(crate) fn new(out: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            out,
            active: Mutex::new(None),
        }
    }

    /// Install the provider and send the offer.
    pub(crate) async fn offer(
        &self,
        features: &[String],
        provider: Arc<dyn ShareProvider>,
        offer: ShareOfferPayload,
    ) -> WshResult<()> {
        if !features.iter().any(|f| f == SHARES_FEATURE) {
            return Err(WshError::Other(
                "this host does not accept shared folders (its features do not include \"shares\")"
                    .into(),
            ));
        }
        if offer.shares.is_empty() || offer.shares.len() > MAX_SHARES {
            return Err(WshError::Other(format!(
                "a share offer names between 1 and {MAX_SHARES} shares"
            )));
        }
        {
            let mut active = self.active.lock().expect("shares");
            if active.is_some() {
                return Err(WshError::Other("shares were already offered".into()));
            }
            *active = Some(Active {
                provider,
                permits: Arc::new(Semaphore::new(offer.max_inflight.max(1) as usize)),
            });
        }
        let frame = frame_encode(&Envelope {
            msg_type: MsgType::ShareOffer,
            payload: Payload::ShareOffer(offer),
        })?;
        self.out
            .send(frame)
            .await
            .map_err(|_| WshError::Transport("outgoing channel closed".into()))
    }

    fn refuse(&self, request_id: u32, errno: &str, message: &str) {
        if let Ok(frame) = frame_encode(&Envelope {
            msg_type: MsgType::ShareReply,
            payload: Payload::ShareReply(error_reply(request_id, errno, message)),
        }) {
            // Best effort: a host that is not reading does not get an answer.
            let _ = self.out.try_send(frame);
        }
    }

    /// Handle one message. Returns true when it was a share message.
    pub(crate) fn on_message(&self, envelope: &Envelope) -> bool {
        let Payload::ShareRequest(request) = &envelope.payload else {
            return false;
        };
        let active = self
            .active
            .lock()
            .expect("shares")
            .as_ref()
            .map(|a| (a.provider.clone(), a.permits.clone()));
        let Some((provider, permits)) = active else {
            self.refuse(request.request_id, "EACCES", "no shares are offered");
            return true;
        };
        let Ok(permit) = permits.try_acquire_owned() else {
            self.refuse(request.request_id, "EAGAIN", "too many requests in flight");
            return true;
        };
        let request = request.clone();
        let out = self.out.clone();
        tokio::spawn(async move {
            let reply = provider.serve(request).await;
            // A host that stopped reading leaves the queue deep: wait (holding the permit, so no
            // new request is taken) instead of queueing more frames.
            while out.capacity() < OUT_RESERVE && !out.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if let Ok(frame) = frame_encode(&Envelope {
                msg_type: MsgType::ShareReply,
                payload: Payload::ShareReply(reply),
            }) {
                let _ = out.send(frame).await;
            }
            drop(permit);
        });
        true
    }

    /// The connection is gone.
    pub(crate) fn shutdown(&self) {
        let active = self.active.lock().expect("shares").take();
        if let Some(a) = active {
            a.provider.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;
    use wsh_core::codec::FrameDecoder;

    /// A provider that answers when told to, and counts what it was asked.
    struct Gate {
        asked: AtomicUsize,
        release: Notify,
        shut: AtomicUsize,
    }

    impl ShareProvider for Gate {
        fn serve<'a>(
            &'a self,
            request: ShareRequestPayload,
        ) -> Pin<Box<dyn Future<Output = ShareReplyPayload> + Send + 'a>> {
            Box::pin(async move {
                self.asked.fetch_add(1, Ordering::SeqCst);
                self.release.notified().await;
                let mut r = error_reply(request.request_id, "EIO", "x");
                r.ok = true;
                r.errno = None;
                r
            })
        }
        fn shutdown(&self) {
            self.shut.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn gate() -> Arc<Gate> {
        Arc::new(Gate {
            asked: AtomicUsize::new(0),
            release: Notify::new(),
            shut: AtomicUsize::new(0),
        })
    }

    fn request(id: u32) -> Envelope {
        Envelope {
            msg_type: MsgType::ShareRequest,
            payload: Payload::ShareRequest(ShareRequestPayload {
                request_id: id,
                share: "s".into(),
                op: "stat".into(),
                path: Some("/".into()),
                to: None,
                handle: None,
                offset: None,
                length: None,
                mode: None,
                flags: vec![],
                cursor: None,
                attr: serde_json::Value::Null,
                data: None,
            }),
        }
    }

    fn offer(max_inflight: u32) -> ShareOfferPayload {
        ShareOfferPayload {
            shares: vec!["s".into()],
            writable: vec![],
            max_inflight,
            max_bytes: 4096,
            paths: None,
        }
    }

    fn replies(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<ShareReplyPayload> {
        let mut dec = FrameDecoder::new();
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            for e in dec.feed::<Envelope>(&frame).expect("decode") {
                if let Payload::ShareReply(r) = e.payload {
                    out.push(r);
                }
            }
        }
        out
    }

    fn features() -> Vec<String> {
        vec![SHARES_FEATURE.to_string()]
    }

    #[tokio::test]
    async fn a_request_before_any_offer_is_refused_and_asks_nothing_of_a_provider() {
        let (tx, mut rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx);
        assert!(hub.on_message(&request(1)));
        let r = replies(&mut rx);
        assert_eq!(r.len(), 1);
        assert!(!r[0].ok);
        assert_eq!(r[0].errno.as_deref(), Some("EACCES"));
    }

    #[tokio::test]
    async fn an_offer_needs_the_hosts_feature_and_is_made_once() {
        let (tx, _rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx);
        let g = gate();
        let no = hub.offer(&[], g.clone(), offer(2)).await;
        assert!(no.is_err(), "a host that did not list `shares`");
        assert!(hub.offer(&features(), g.clone(), offer(2)).await.is_ok());
        assert!(hub.offer(&features(), g.clone(), offer(2)).await.is_err());
        let (tx, _rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx);
        let empty = ShareOfferPayload {
            shares: vec![],
            ..offer(2)
        };
        assert!(hub.offer(&features(), g, empty).await.is_err());
    }

    #[tokio::test]
    async fn requests_beyond_the_window_are_refused_at_once_never_queued() {
        let (tx, mut rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx);
        let g = gate();
        hub.offer(&features(), g.clone(), offer(2)).await.unwrap();
        let _offer_frame = rx.recv().await.unwrap();
        for id in 1..=10 {
            assert!(hub.on_message(&request(id)));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            g.asked.load(Ordering::SeqCst),
            2,
            "only the window reached the provider"
        );
        let refused = replies(&mut rx);
        assert_eq!(refused.len(), 8);
        assert!(refused
            .iter()
            .all(|r| !r.ok && r.errno.as_deref() == Some("EAGAIN")));
        g.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let done = replies(&mut rx);
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(|r| r.ok));
        // The slots are free again.
        assert!(hub.on_message(&request(11)));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(g.asked.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_host_that_stops_reading_gets_no_more_replies_queued_than_a_few() {
        // A small outgoing queue (the real one is 256 deep): once it is more than 1/4 full no reply is
        // queued, so the provider's replies wait instead of piling up in memory.
        let (tx, mut rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx.clone());
        let g = gate();
        hub.offer(&features(), g.clone(), offer(16)).await.unwrap();
        let _ = rx.recv().await;
        // Fill the queue past the reserve with something else (the host is not reading).
        for _ in 0..200 {
            tx.send(vec![0u8; 8]).await.unwrap();
        }
        for id in 1..=4 {
            hub.on_message(&request(id));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        g.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            rx.len(),
            200,
            "no reply was queued while the queue was deep"
        );
        // The host reads again: the replies come.
        let mut n = 0;
        while rx.len() > 40 {
            rx.recv().await.unwrap();
            n += 1;
        }
        assert!(n >= 100, "drained {n}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut got = 0;
        while let Ok(f) = rx.try_recv() {
            // A fresh decoder per frame: the filler frames are not wsh frames.
            if let Ok(es) = FrameDecoder::new().feed::<Envelope>(&f) {
                got += es
                    .iter()
                    .filter(|e| matches!(e.payload, Payload::ShareReply(_)))
                    .count();
            }
        }
        assert_eq!(got, 4, "all four replies arrived once the queue drained");
    }

    #[tokio::test]
    async fn shutdown_tells_the_provider_once() {
        let (tx, _rx) = mpsc::channel(256);
        let hub = ShareHub::new(tx);
        let g = gate();
        hub.offer(&features(), g.clone(), offer(2)).await.unwrap();
        hub.shutdown();
        hub.shutdown();
        assert_eq!(g.shut.load(Ordering::SeqCst), 1);
        // And after it, nothing is served.
        let (tx, mut rx) = mpsc::channel(256);
        let hub2 = ShareHub::new(tx);
        hub2.on_message(&request(1));
        assert!(!replies(&mut rx)[0].ok);
    }
}
