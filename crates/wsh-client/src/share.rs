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
