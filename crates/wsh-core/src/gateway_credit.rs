//! Flow control for gateway connections (`GatewayCredit`, feature `gateway-credit`), shared by
//! the server and the client.
//!
//! When both ends negotiate the feature, each direction of each connection starts with
//! [`GATEWAY_CREDIT_WINDOW`] bytes of credit. A sender sends only while it holds credit and
//! waits for a `GatewayCredit` otherwise; the receiver returns credit as its application
//! consumes data. A peer that sends beyond the credit it was given has broken the protocol and
//! its connection is closed. Without the feature nothing is metered.

use std::sync::Mutex;
use tokio::sync::Notify;

/// Credit each direction of a connection starts with when `gateway-credit` is negotiated (a
/// protocol constant).
pub const GATEWAY_CREDIT_WINDOW: usize = 262_144;
/// Feature string: the client lists it in `Hello.features`, the host in `ServerHello.features`;
/// both = credit is on.
pub const GATEWAY_CREDIT_FEATURE: &str = "gateway-credit";
/// Largest `GatewayData` payload this implementation sends.
pub const GATEWAY_MAX_FRAME: usize = 65_536;

/// How much a sender may still send. Unlimited when credit is not negotiated.
#[derive(Debug)]
pub struct SendCredit {
    limited: bool,
    avail: Mutex<u64>,
    notify: Notify,
}

impl SendCredit {
    /// `limited`: credit was negotiated, so start with the initial window.
    pub fn new(limited: bool) -> Self {
        Self {
            limited,
            avail: Mutex::new(if limited {
                GATEWAY_CREDIT_WINDOW as u64
            } else {
                0
            }),
            notify: Notify::new(),
        }
    }

    /// Wait until there is credit and take up to `want` bytes of it.
    pub async fn take(&self, want: usize) -> usize {
        if !self.limited {
            return want;
        }
        loop {
            {
                let mut avail = self.avail.lock().expect("credit lock");
                if *avail > 0 {
                    let n = (*avail).min(want as u64);
                    *avail -= n;
                    return n as usize;
                }
            }
            self.notify.notified().await;
        }
    }

    /// All `n` bytes or none (a datagram cannot be split).
    pub fn try_take_exact(&self, n: usize) -> bool {
        if !self.limited {
            return true;
        }
        let mut avail = self.avail.lock().expect("credit lock");
        if *avail >= n as u64 {
            *avail -= n as u64;
            true
        } else {
            false
        }
    }

    /// A `GatewayCredit` arrived.
    pub fn grant(&self, n: u32) {
        if !self.limited {
            return;
        }
        let mut avail = self.avail.lock().expect("credit lock");
        *avail = avail.saturating_add(u64::from(n));
        drop(avail);
        self.notify.notify_one();
    }

    /// Wake a waiting sender so it can notice the connection is over.
    pub fn wake(&self) {
        self.notify.notify_one();
    }

    /// Credit currently held (for tests).
    pub fn available(&self) -> u64 {
        *self.avail.lock().expect("credit lock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn a_sender_holds_the_initial_window_then_waits_for_credit() {
        let c = Arc::new(SendCredit::new(true));
        assert_eq!(
            c.take(GATEWAY_CREDIT_WINDOW * 2).await,
            GATEWAY_CREDIT_WINDOW
        );
        let waiting = {
            let c = c.clone();
            tokio::spawn(async move { c.take(10).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "no credit: the sender waits");
        c.grant(4);
        assert_eq!(waiting.await.unwrap(), 4);
    }

    #[tokio::test]
    async fn unmetered_never_waits() {
        let c = SendCredit::new(false);
        assert_eq!(c.take(1 << 20).await, 1 << 20);
        c.grant(5);
        assert!(c.try_take_exact(usize::MAX / 2));
    }

    #[test]
    fn a_datagram_is_all_or_nothing() {
        let c = SendCredit::new(true);
        assert!(c.try_take_exact(GATEWAY_CREDIT_WINDOW - 10));
        assert!(!c.try_take_exact(11));
        assert_eq!(c.available(), 10);
        assert!(c.try_take_exact(10));
    }
}
