//! Flow control for an `rpc` channel in virtual data mode (wsh #191), shared by the client and the server;
//! the Rust twin of `RpcCreditLink` in `src/rpc-virtual.mjs`.
//!
//! A host on a connection without client-opened data streams (a sealed session, a host behind a relay) states
//! `rpc-virtual` instead of `rpc`, and the channel's CBOR sequence rides `SessionData` (inside `EncryptedFrame`
//! on a sealed session). The control plane has no flow control of its own, so the link meters the bytes:
//!
//! - each direction starts with [`RPC_CREDIT_WINDOW`] bytes of credit; a writer sends only while it holds credit
//!   and waits for a `GatewayCredit` otherwise, so a reader that does not read bounds the sender;
//! - the receiver returns credit as the application takes bytes in, in bytes and not in messages, in batches of
//!   half a window, so a message larger than the window still arrives;
//! - a peer that sends more than the credit it was given has broken the protocol and the channel is closed.
//!
//! The credit travels as `GatewayCredit` with `gateway_id = RPC_CREDIT_FLAG | channel_id`, a number space
//! beside the gateway's own ids (which count up from 1).

use std::sync::Mutex;
use tokio::sync::Notify;

/// `ServerHello` / `ReverseAccept` feature: the host serves `rpc` channels in virtual data mode.
pub const RPC_VIRTUAL_FEATURE: &str = "rpc-virtual";
/// Credit each direction of a virtual-mode rpc channel starts with, in bytes (a protocol constant).
pub const RPC_CREDIT_WINDOW: usize = 262_144;
/// `GatewayCredit.gateway_id` bit that marks credit for an rpc channel; the rest is the channel id.
pub const RPC_CREDIT_FLAG: u32 = 0x8000_0000;
/// Largest `SessionData` payload an rpc channel sends.
pub const RPC_VIRTUAL_CHUNK_BYTES: usize = 32 * 1024;

/// The `GatewayCredit.gateway_id` that grants credit on rpc channel `channel_id`.
pub fn rpc_credit_id(channel_id: u32) -> u32 {
    RPC_CREDIT_FLAG | channel_id
}

/// The rpc channel a `GatewayCredit.gateway_id` is for, or `None` if it is not rpc credit.
pub fn rpc_channel_of_credit(gateway_id: u32) -> Option<u32> {
    (gateway_id >= RPC_CREDIT_FLAG).then(|| gateway_id - RPC_CREDIT_FLAG)
}

/// The link was closed while a writer waited for credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkClosed;

#[derive(Debug)]
struct State {
    /// Credit this end may still spend.
    credit: u64,
    /// Credit this end has granted the peer and not yet seen spent.
    peer_credit: i64,
    /// Bytes taken in and not yet returned as credit.
    owed: u64,
    closed: bool,
}

/// One end of the byte pipe under a virtual-mode rpc channel.
#[derive(Debug)]
pub struct CreditLink {
    window: usize,
    chunk: usize,
    state: Mutex<State>,
    notify: Notify,
}

impl Default for CreditLink {
    fn default() -> Self {
        Self::new()
    }
}

impl CreditLink {
    pub fn new() -> Self {
        Self::with_window(RPC_CREDIT_WINDOW, RPC_VIRTUAL_CHUNK_BYTES)
    }

    pub fn with_window(window: usize, chunk: usize) -> Self {
        Self {
            window,
            chunk: chunk.max(1),
            state: Mutex::new(State {
                credit: window as u64,
                peer_credit: window as i64,
                owed: 0,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    /// Credit this end holds to send with.
    pub fn credit(&self) -> u64 {
        self.state.lock().expect("credit lock").credit
    }

    /// Wait for credit and take up to `want` bytes of it (at most one chunk): the number of bytes the caller may now send.
    /// Fails if the link closes first.
    pub async fn reserve(&self, want: usize) -> Result<usize, LinkClosed> {
        loop {
            // Registered before the state is looked at, so a grant between the look and the wait is not lost.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut s = self.state.lock().expect("credit lock");
                if s.closed {
                    return Err(LinkClosed);
                }
                if s.credit > 0 {
                    let n = (want.min(self.chunk) as u64).min(s.credit);
                    s.credit -= n;
                    return Ok(n as usize);
                }
            }
            notified.await;
        }
    }

    /// The peer granted `n` more bytes (a `GatewayCredit`).
    pub fn grant(&self, n: u64) {
        let mut s = self.state.lock().expect("credit lock");
        if s.closed || n == 0 {
            return;
        }
        s.credit = s.credit.saturating_add(n);
        drop(s);
        self.notify.notify_waiters();
    }

    /// Account for `n` bytes the peer sent (a `SessionData`). Returns false if that is more than the credit this end
    /// granted: the caller must then not deliver them and must close the channel.
    pub fn receive(&self, n: usize) -> bool {
        let mut s = self.state.lock().expect("credit lock");
        if s.closed {
            return false;
        }
        s.peer_credit -= n as i64;
        s.peer_credit >= 0
    }

    /// The application took `n` received bytes in. Returns the credit to hand the peer back now (a `GatewayCredit`), in
    /// batches of half a window.
    pub fn consumed(&self, n: usize) -> Option<u64> {
        let mut s = self.state.lock().expect("credit lock");
        if s.closed {
            return None;
        }
        s.owed += n as u64;
        if s.owed >= (self.window / 2) as u64 {
            let give = s.owed;
            s.owed = 0;
            s.peer_credit += give as i64;
            Some(give)
        } else {
            None
        }
    }

    /// The channel is over: writers waiting for credit are released with an error.
    pub fn close(&self) {
        self.state.lock().expect("credit lock").closed = true;
        self.notify.notify_waiters();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("credit lock").closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn the_credit_id_is_flagged_and_gateway_ids_are_not() {
        assert_eq!(rpc_credit_id(5), 0x8000_0005);
        assert_eq!(rpc_channel_of_credit(0x8000_0005), Some(5));
        assert_eq!(rpc_channel_of_credit(1), None);
        assert_eq!(rpc_channel_of_credit(0x7fff_ffff), None);
    }

    #[tokio::test]
    async fn a_writer_holds_one_window_then_waits_for_credit() {
        let link = Arc::new(CreditLink::with_window(100, 40));
        let mut sent = 0;
        while sent < 100 {
            let n = link.reserve(1000).await.unwrap();
            assert!(n <= 40, "a chunk is at most the chunk size");
            sent += n;
        }
        assert_eq!(sent, 100);
        let waiting = {
            let l = link.clone();
            tokio::spawn(async move { l.reserve(10).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "no credit: the sender waits");
        link.grant(4);
        assert_eq!(waiting.await.unwrap(), Ok(4));
    }

    #[tokio::test]
    async fn closing_releases_a_waiting_writer_with_an_error() {
        let link = Arc::new(CreditLink::with_window(10, 10));
        assert_eq!(link.reserve(10).await, Ok(10));
        let waiting = {
            let l = link.clone();
            tokio::spawn(async move { l.reserve(1).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        link.close();
        assert_eq!(waiting.await.unwrap(), Err(LinkClosed));
    }

    #[test]
    fn a_peer_that_overruns_its_credit_is_reported() {
        let link = CreditLink::with_window(100, 10);
        assert!(link.receive(60));
        assert!(link.receive(40), "exactly the window is fine");
        assert!(!link.receive(1), "one byte more is an overrun");
    }

    #[test]
    fn credit_comes_back_in_half_windows_and_covers_what_was_taken_in() {
        let link = CreditLink::with_window(100, 10);
        assert!(link.receive(100));
        assert_eq!(link.consumed(30), None, "less than half a window: kept");
        assert_eq!(
            link.consumed(30),
            Some(60),
            "half a window reached: all of it returned"
        );
        // the returned credit is the peer's to spend again
        assert!(link.receive(60));
        assert!(!link.receive(1));
    }

    #[test]
    fn a_closed_link_neither_returns_credit_nor_accepts_data() {
        let link = CreditLink::with_window(100, 10);
        link.close();
        assert!(link.is_closed());
        assert_eq!(link.consumed(100), None);
        assert!(!link.receive(1));
        link.grant(5);
        assert_eq!(link.credit(), 100, "a grant after close changes nothing");
    }
}
