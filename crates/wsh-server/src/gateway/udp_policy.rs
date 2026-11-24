//! Bounds of the UDP flows (`OpenUdp`, wsh #98, #124, #145), the Node host's `gateway.udp`
//! (`src/server/udp-policy.mjs`) with the same defaults.
//!
//! A UDP flow is a socket the host opens on the client's behalf, to ONE destination fixed at
//! `OpenUdp`, so the risks are the host being used as a packet cannon and as an amplifier (a small
//! query that makes a big answer, repeated). Everything is therefore bounded in count and rate-limited
//! in BOTH directions, and a datagram over a limit is dropped, as a congested network would:
//!
//! - `udp_max_flows` (16) concurrent flows per client connection;
//! - `udp_packets_per_second_per_flow` (500) and `udp_packets_per_second_per_client` (2000), token
//!   buckets over datagrams; `udp_bytes_per_second_per_client` (4 MiB), the same over payload bytes,
//!   which is what bounds amplification. `0` means no limit;
//! - `udp_idle_secs` (60): a flow with no datagram in either direction for this long is closed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_FLOWS: usize = 16;
pub const DEFAULT_PACKETS_PER_SECOND_PER_FLOW: u64 = 500;
pub const DEFAULT_PACKETS_PER_SECOND_PER_CLIENT: u64 = 2000;
pub const DEFAULT_BYTES_PER_SECOND_PER_CLIENT: u64 = 4 * 1024 * 1024;
pub const DEFAULT_IDLE_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPolicy {
    pub max_flows: usize,
    /// `0`: no limit (as every rate below).
    pub packets_per_second_per_flow: u64,
    pub packets_per_second_per_client: u64,
    pub bytes_per_second_per_client: u64,
    pub idle: Duration,
}

impl Default for UdpPolicy {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            packets_per_second_per_flow: DEFAULT_PACKETS_PER_SECOND_PER_FLOW,
            packets_per_second_per_client: DEFAULT_PACKETS_PER_SECOND_PER_CLIENT,
            bytes_per_second_per_client: DEFAULT_BYTES_PER_SECOND_PER_CLIENT,
            idle: Duration::from_secs(DEFAULT_IDLE_SECS),
        }
    }
}

impl UdpPolicy {
    pub fn new(
        max_flows: usize,
        packets_per_second_per_flow: u64,
        packets_per_second_per_client: u64,
        bytes_per_second_per_client: u64,
        idle_secs: u64,
    ) -> Result<Self, String> {
        if idle_secs == 0 {
            return Err(
                "config: [gateway] udp_idle_secs must be at least 1 (a flow that is never closed would hold a socket for ever)"
                    .into(),
            );
        }
        Ok(Self {
            max_flows,
            packets_per_second_per_flow,
            packets_per_second_per_client,
            bytes_per_second_per_client,
            idle: Duration::from_secs(idle_secs),
        })
    }

    /// The bucket for one flow's datagrams (burst: a quarter second, at least 16).
    pub fn flow_packets(&self) -> TokenBucket {
        TokenBucket::new(self.packets_per_second_per_flow, 16.0)
    }

    /// The bucket for all of a client's datagrams (burst: a quarter second, at least 32).
    pub fn client_packets(&self) -> TokenBucket {
        TokenBucket::new(self.packets_per_second_per_client, 32.0)
    }

    /// The bucket for all of a client's payload bytes (burst: a quarter second, at least 64 KiB).
    pub fn client_bytes(&self) -> TokenBucket {
        TokenBucket::new(self.bytes_per_second_per_client, 65536.0)
    }
}

/// A token bucket: `rate` tokens a second, up to a burst of a quarter second's worth (at least
/// `min_burst`). A rate of `0` takes everything.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub fn new(rate_per_second: u64, min_burst: f64) -> Self {
        let rate = rate_per_second as f64;
        let burst = (rate / 4.0).max(min_burst).max(1.0);
        Self {
            rate,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    /// Take `cost` tokens if they are there.
    pub fn take(&self, cost: usize) -> bool {
        if self.rate == 0.0 {
            return true;
        }
        let mut s = self.state.lock().expect("bucket");
        let now = Instant::now();
        let refill = now.duration_since(s.1).as_secs_f64() * self.rate;
        s.0 = (s.0 + refill).min(self.burst);
        s.1 = now;
        if s.0 < cost as f64 {
            return false;
        }
        s.0 -= cost as f64;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_allows_its_burst_then_refuses_and_a_zero_rate_never_refuses() {
        let b = TokenBucket::new(40, 16.0); // burst max(10, 16) = 16
        let admitted = (0..100).filter(|_| b.take(1)).count();
        assert!((16..=17).contains(&admitted), "{admitted}");
        let unlimited = TokenBucket::new(0, 16.0);
        assert!((0..10_000).all(|_| unlimited.take(1_000_000)));
    }

    #[test]
    fn a_bucket_refills_with_time() {
        let b = TokenBucket::new(1000, 1.0); // burst 250
        assert!(b.take(250));
        assert!(!b.take(250));
        std::thread::sleep(Duration::from_millis(400));
        assert!(b.take(250), "400 ms at 1000/s refills the burst");
    }

    #[test]
    fn bytes_are_costed_by_size() {
        let b = TokenBucket::new(1_000_000, 65536.0); // burst 250000
        assert!(b.take(200_000));
        assert!(!b.take(200_000));
        assert!(b.take(40_000));
    }

    #[test]
    fn an_idle_of_zero_is_refused() {
        assert!(UdpPolicy::new(16, 500, 2000, 4 << 20, 0).is_err());
        assert_eq!(
            UdpPolicy::new(16, 500, 2000, 4 << 20, 60).unwrap(),
            UdpPolicy::default()
        );
    }
}
