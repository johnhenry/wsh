//! Noticing a local peer that half-closed and then went away (wsh #282).
//!
//! A socket whose peer sent its FIN (it will send no more and may still read) and was then killed
//! tells a plain `read`/`write` loop nothing: the read already ended, and the kernel reports the
//! vanished peer to a writer only. The kernel does report it as a hang-up of the socket's write
//! side, though, and tokio exposes that readiness (`Ready::is_write_closed`). A [`PeerWatch`] waits
//! for it on a duplicate of the socket's descriptor, so the pump or relay that owns the socket
//! itself is not disturbed, and nothing is ever written to the peer.
//!
//! What the kernel reports, by kind:
//!
//! * unix socket: a peer that is alive and half-closed shows no hang-up; a peer that has gone away
//!   shows one at once (kqueue: `EVFILT_WRITE` with `EV_EOF`; epoll: `EPOLLHUP`).
//! * TCP: nothing while the peer's kernel still answers. A peer that half-closed and exited leaves
//!   a socket that acknowledges everything except data, until its kernel drops it (60 s by default
//!   on Linux and macOS); a keep-alive probe after that is answered with a reset, which is a
//!   hang-up. A peer that died with data unread resets the connection at once. So a TCP socket is
//!   given a short keep-alive schedule (see [`PeerWatch::arm`]) when it becomes half-closed, and
//!   detection is bounded by that kernel timeout, not by the schedule.
//!
//! Windows: not covered (named pipes and TCP there behave differently); [`PeerWatch`] cannot be
//! made and callers go on without it.

use std::io;
use std::time::Duration;

/// The TCP keep-alive schedule given to a socket that becomes half-closed: first probe after this
/// long, then one per this long, three in all. (Also the default of `[gateway] half_close_probe_secs`.)
pub const DEFAULT_HALF_CLOSE_PROBE: Duration = Duration::from_secs(2);

/// A local socket whose half-closed peer can be watched. `None` where the platform cannot.
pub trait WatchablePeer {
    fn peer_watch(&self) -> Option<PeerWatch>;
}

impl WatchablePeer for tokio::net::TcpStream {
    fn peer_watch(&self) -> Option<PeerWatch> {
        PeerWatch::tcp(self).ok()
    }
}

#[cfg(unix)]
impl WatchablePeer for tokio::net::UnixStream {
    fn peer_watch(&self) -> Option<PeerWatch> {
        PeerWatch::unix(self).ok()
    }
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::fd::{AsFd, OwnedFd};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{Interest, Ready};

    /// Waits for the hang-up of a socket's write side. Holds a duplicate of the descriptor: drop
    /// it when the connection is over (the socket is not closed for good before that). Nothing is
    /// registered with the reactor, and nothing is changed on the socket, until it is used
    /// ([`PeerWatch::arm`], [`PeerWatch::gone`]): a connection that never half-closes costs one
    /// descriptor.
    pub struct PeerWatch {
        fd: OwnedFd,
        tcp: bool,
    }

    impl PeerWatch {
        /// Watch a TCP stream. Must be called inside a tokio runtime.
        pub fn tcp(s: &tokio::net::TcpStream) -> io::Result<Self> {
            Self::of(s.as_fd(), true)
        }

        /// Watch a unix stream. Must be called inside a tokio runtime.
        pub fn unix(s: &tokio::net::UnixStream) -> io::Result<Self> {
            Self::of(s.as_fd(), false)
        }

        fn of(fd: std::os::fd::BorrowedFd<'_>, tcp: bool) -> io::Result<Self> {
            Ok(Self {
                fd: fd.try_clone_to_owned()?,
                tcp,
            })
        }

        /// The socket has become half-closed: a TCP socket gets keep-alive on a short schedule
        /// (first probe after `every`, then one per `every`, three in all; whole seconds, at
        /// least one), so the kernel learns that a peer that exited is gone. Nothing for a unix
        /// socket (its hang-up is immediate). Only called for a half-closed socket: an ordinary
        /// connection is left as it was.
        pub fn arm(&self, every: Duration) {
            if !self.tcp {
                return;
            }
            let secs = Duration::from_secs(every.as_secs().max(1));
            let ka = socket2::TcpKeepalive::new()
                .with_time(secs)
                .with_interval(secs);
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd"
            ))]
            let ka = ka.with_retries(3);
            let _ = socket2::SockRef::from(&self.fd).set_tcp_keepalive(&ka);
        }

        /// Resolves when the peer is seen to have gone away (a hang-up or error on the socket's
        /// write side). Never resolves for a peer that is alive, however long it stays quiet.
        /// Must be awaited inside a tokio runtime.
        pub async fn gone(&self) {
            let Ok(fd) = self
                .fd
                .try_clone()
                .and_then(|fd| AsyncFd::with_interest(fd, Interest::WRITABLE))
            else {
                return std::future::pending().await;
            };
            loop {
                let Ok(mut guard) = fd.ready(Interest::WRITABLE).await else {
                    return std::future::pending().await;
                };
                let ready = guard.ready();
                if ready.is_write_closed() || ready.is_error() {
                    return;
                }
                guard.clear_ready_matching(Ready::WRITABLE);
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    /// Not available on this platform: it cannot be made, so callers go on without one.
    pub struct PeerWatch(());

    impl PeerWatch {
        pub fn tcp(_: &tokio::net::TcpStream) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "watching a half-closed peer is not available on this platform",
            ))
        }
        pub fn arm(&self, _: Duration) {}
        pub async fn gone(&self) {
            std::future::pending().await
        }
    }
}

pub use imp::PeerWatch;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream, UnixStream};

    /// A bound on how long a hang-up that is already there may take to be seen: far above what it
    /// needs (it is immediate), so a loaded machine does not fail it; it is not waited for in full.
    const SEEN: Duration = Duration::from_secs(20);
    /// How long a live peer is watched before it is called alive: nothing can happen in that time,
    /// the wait only gives a wrong answer a chance to show.
    const QUIET: Duration = Duration::from_millis(400);

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        (s, c)
    }

    #[tokio::test]
    async fn a_half_closed_unix_peer_that_is_alive_is_not_gone() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let w = a.peer_watch().expect("unix sockets can be watched");
        b.shutdown().await.unwrap(); // its FIN: half-closed, still reading
        assert!(tokio::time::timeout(QUIET, w.gone()).await.is_err());
        drop(b);
        tokio::time::timeout(SEEN, w.gone())
            .await
            .expect("the hang-up of a peer that went away is seen");
    }

    #[tokio::test]
    async fn a_unix_peer_that_went_away_before_the_watch_began_is_seen() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.shutdown().await.unwrap();
        drop(b);
        let w = a.peer_watch().unwrap();
        tokio::time::timeout(SEEN, w.gone()).await.expect("seen");
    }

    #[tokio::test]
    async fn the_watch_never_writes_a_byte_to_a_live_peer() {
        use tokio::io::AsyncReadExt;
        let (a, mut b) = UnixStream::pair().unwrap();
        let w = a.peer_watch().unwrap();
        w.arm(Duration::from_secs(1));
        assert!(tokio::time::timeout(QUIET, w.gone()).await.is_err());
        let mut got = [0u8; 8];
        // a's side sent nothing: b has nothing to read (a read that returns anything before the timeout is a byte)
        assert!(
            tokio::time::timeout(Duration::from_millis(100), b.read(&mut got))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_tcp_peer_that_is_reset_after_half_closing_is_seen() {
        let (a, mut b) = tcp_pair().await;
        let w = a.peer_watch().unwrap();
        w.arm(DEFAULT_HALF_CLOSE_PROBE);
        b.shutdown().await.unwrap();
        // Alive and half-closed: quiet, whatever the keep-alive does.
        assert!(tokio::time::timeout(QUIET, w.gone()).await.is_err());
        // Gone with unread data (here: a linger of zero, so closing resets): the reset is a hang-up.
        socket2::SockRef::from(&b)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(b);
        tokio::time::timeout(SEEN, w.gone())
            .await
            .expect("the reset is seen");
    }

    #[tokio::test]
    async fn arming_a_tcp_socket_only_sets_keep_alive_and_changes_nothing_else() {
        let (a, _b) = tcp_pair().await;
        let w = a.peer_watch().unwrap();
        w.arm(Duration::from_millis(10)); // rounded up to a whole second, at least one
        let sock = socket2::SockRef::from(&a);
        assert!(sock.keepalive().unwrap());
        assert!(a.nodelay().is_ok());
    }

    #[tokio::test]
    async fn dropping_the_watch_releases_the_descriptor() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let w = a.peer_watch().unwrap();
        drop(w);
        drop(a);
        // With the watch gone the last descriptor of `a` is closed: its peer reads the end of file.
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(SEEN, b.read(&mut buf))
            .await
            .expect("the peer sees the close")
            .unwrap();
        assert_eq!(n, 0);
    }
}
