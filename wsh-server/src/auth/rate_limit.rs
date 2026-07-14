//! Sliding-window rate limiter for auth and attach attempts.
//!
//! Uses a simple token-bucket style approach with per-key counters
//! that decay over a rolling window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A rate limiter with configurable per-key limits and window duration.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum attempts allowed within the window.
    max_attempts: u32,
    /// Duration of the sliding window.
    window: Duration,
    /// Per-key tracking: key → list of attempt timestamps.
    entries: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_attempts` - Maximum allowed attempts within the window.
    /// * `window_secs` - Window duration in seconds.
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            max_attempts,
            window: Duration::from_secs(window_secs),
            entries: HashMap::new(),
        }
    }

    /// Check if an attempt is allowed for the given key, and record it if so.
    ///
    /// Returns `true` if allowed, `false` if rate-limited.
    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let attempts = self.entries.entry(key.to_string()).or_default();

        // Remove expired entries
        attempts.retain(|t| *t > cutoff);

        if attempts.len() as u32 >= self.max_attempts {
            return false;
        }

        attempts.push(now);
        true
    }

    /// Check if an attempt would be allowed without recording it.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        match self.entries.get(key) {
            Some(attempts) => {
                let active = attempts.iter().filter(|t| **t > cutoff).count();
                (active as u32) < self.max_attempts
            }
            None => true,
        }
    }

    /// Garbage-collect expired entries to prevent memory growth.
    pub fn gc(&mut self) {
        let now = Instant::now();
        let cutoff = now - self.window;

        self.entries.retain(|_, attempts| {
            attempts.retain(|t| *t > cutoff);
            !attempts.is_empty()
        });
    }
}

/// Pre-configured rate limiters for the wsh server.
#[derive(Debug)]
pub struct ServerRateLimits {
    /// Auth attempts: max 5 per minute per IP address.
    pub auth: RateLimiter,
    /// Attach attempts: max 10 per minute per principal (fingerprint).
    pub attach: RateLimiter,
}

impl Default for ServerRateLimits {
    fn default() -> Self {
        Self {
            auth: RateLimiter::new(5, 60),
            attach: RateLimiter::new(10, 60),
        }
    }
}

impl ServerRateLimits {
    /// Check if an auth attempt from the given IP is allowed.
    pub fn check_auth(&mut self, ip: &IpAddr) -> bool {
        self.auth.check_and_record(&ip.to_string())
    }

    /// Check if an attach attempt from the given principal is allowed.
    pub fn check_attach(&mut self, fingerprint: &str) -> bool {
        self.attach.check_and_record(fingerprint)
    }

    /// Run garbage collection on all limiters.
    pub fn gc(&mut self) {
        self.auth.gc();
        self.attach.gc();
    }
}
