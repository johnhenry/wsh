//! One accepted reverse-tunnel connection (wsh #145): a stream that counts itself against its
//! listener while it exists, and closes itself when it has been idle for too long.
//!
//! The count is the listener's `reverse_max_connections_per_listener`: a slot is taken when the
//! connection is accepted from the network and released when the stream is dropped, whichever way
//! that happens (the client never answered, rejected it, or the relay ended). The idle limit is
//! `reverse_idle_secs`: a read that has waited that long since the last byte moved in EITHER
//! direction fails with `TimedOut`, which ends the relay. Only reads poll the timer (a timer polled
//! from both halves of a split stream would keep just one waker); writes only push the deadline back.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// A place in a listener's connection count, given back on drop.
#[derive(Debug)]
pub struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// Take a slot if the listener has fewer than `max` open; `None` when it is full.
    pub fn take(open: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        // One accept loop per listener calls this, but compare-and-swap keeps it right regardless.
        let mut cur = open.load(Ordering::Acquire);
        loop {
            if cur >= max {
                return None;
            }
            match open.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Slot(open.clone())),
                Err(now) => cur = now,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct ReverseConn<S> {
    inner: S,
    _slot: Slot,
    idle: Option<(Duration, Pin<Box<Sleep>>)>,
}

impl<S> ReverseConn<S> {
    pub fn new(inner: S, slot: Slot, idle: Option<Duration>) -> Self {
        Self {
            inner,
            _slot: slot,
            idle: idle.map(|d| (d, Box::pin(tokio::time::sleep(d)))),
        }
    }

    fn touch(&mut self) {
        if let Some((d, sleep)) = &mut self.idle {
            sleep.as_mut().reset(Instant::now() + *d);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReverseConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    self.touch();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if let Some((_, sleep)) = &mut self.idle {
                    if sleep.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "reverse connection idle",
                        )));
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReverseConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn slots_are_counted_and_given_back() {
        let open = Arc::new(AtomicUsize::new(0));
        let a = Slot::take(&open, 2).unwrap();
        let b = Slot::take(&open, 2).unwrap();
        assert!(Slot::take(&open, 2).is_none(), "full");
        drop(a);
        let c = Slot::take(&open, 2).expect("a place came free");
        assert_eq!(open.load(Ordering::SeqCst), 2);
        drop((b, c));
        assert_eq!(open.load(Ordering::SeqCst), 0);
    }

    // Real time, wide margins (the workspace has no tokio `test-util`): the limit is 1 s and traffic
    // comes every 100 ms, so a loaded machine would have to stall 10x to fail a test.

    #[tokio::test]
    async fn a_read_with_no_traffic_times_out_and_gives_its_slot_back_on_drop() {
        let (a, _b) = tokio::io::duplex(64);
        let open = Arc::new(AtomicUsize::new(0));
        let slot = Slot::take(&open, 1).unwrap();
        let mut conn = ReverseConn::new(a, slot, Some(Duration::from_millis(300)));
        let started = std::time::Instant::now();
        let mut buf = [0u8; 8];
        let e = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "not before the limit"
        );
        assert_eq!(
            open.load(Ordering::SeqCst),
            1,
            "still counted while it exists"
        );
        drop(conn);
        assert_eq!(open.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn bytes_in_either_direction_defer_the_idle_limit() {
        let (a, mut b) = tokio::io::duplex(64);
        let open = Arc::new(AtomicUsize::new(0));
        let conn = ReverseConn::new(
            a,
            Slot::take(&open, 1).unwrap(),
            Some(Duration::from_secs(1)),
        );
        let (mut rd, mut wr) = tokio::io::split(conn);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            rd.read(&mut buf).await
        });
        // 2 s of writes from the connection's own side, one every 100 ms: the 1 s limit never trips
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            wr.write_all(b"x").await.unwrap();
            let mut sink = [0u8; 8];
            let _ = b.read(&mut sink).await;
        }
        assert!(!reader.is_finished(), "writes kept it alive");
        // then silence: now it times out
        let r = tokio::time::timeout(Duration::from_secs(10), reader)
            .await
            .expect("it timed out in the end")
            .unwrap();
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn without_an_idle_limit_a_read_waits() {
        let (a, mut b) = tokio::io::duplex(64);
        let open = Arc::new(AtomicUsize::new(0));
        let mut conn = ReverseConn::new(a, Slot::take(&open, 1).unwrap(), None);
        let mut buf = [0u8; 8];
        let waited = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut buf)).await;
        assert!(waited.is_err(), "no limit: still waiting");
        b.write_all(b"hi").await.unwrap();
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
    }
}
