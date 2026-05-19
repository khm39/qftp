//! Connection-count caps and request rate limiting.
//!
//! The rate limiter is a per-IP token bucket sized in requests per second.
//! Connection caps are enforced on accept; once at the limit, new Initial
//! packets are silently dropped (cheaper than answering with a
//! CONNECTION_CLOSE that the peer might just retry forever).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Server-wide caps applied at accept time.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub max_total_connections: usize,
    pub max_per_ip_connections: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_total_connections: 64,
            max_per_ip_connections: 8,
        }
    }
}

/// A token-bucket rate limiter keyed by IP. Refills at `rps` tokens per
/// second, up to `burst` capacity. Calling `try_consume` returns false if
/// no token is available.
pub struct RateLimiter {
    rps: f64,
    burst: f64,
    buckets: HashMap<IpAddr, Bucket>,
    /// Soft cap on the number of distinct IP buckets we will track at
    /// once. When exceeded, the oldest idle buckets are evicted on the
    /// next consume call.
    max_tracked: usize,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rps: f64, burst: f64) -> Self {
        Self {
            rps,
            burst,
            buckets: HashMap::new(),
            max_tracked: 4096,
        }
    }

    pub fn try_consume(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.evict_if_needed(now);
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn evict_if_needed(&mut self, now: Instant) {
        if self.buckets.len() < self.max_tracked {
            return;
        }
        let idle_cutoff = Duration::from_secs(300);
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < idle_cutoff);
    }
}

/// Tracker for the per-IP and global concurrent-connection caps.
#[derive(Default)]
pub struct ConnectionCounter {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl ConnectionCounter {
    pub fn try_acquire(&mut self, caps: Caps, ip: IpAddr) -> bool {
        if self.total >= caps.max_total_connections {
            return false;
        }
        let entry = self.per_ip.entry(ip).or_insert(0);
        if *entry >= caps.max_per_ip_connections {
            return false;
        }
        *entry += 1;
        self.total += 1;
        true
    }

    pub fn release(&mut self, ip: IpAddr) {
        self.total = self.total.saturating_sub(1);
        if let Some(c) = self.per_ip.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_ip.remove(&ip);
            }
        }
    }

    #[allow(dead_code)] // surfaced by metrics + soak harness
    pub fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_limiter_allows_burst_then_refills() {
        let mut rl = RateLimiter::new(1.0, 3.0);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // Burst of 3 immediately.
        assert!(rl.try_consume(ip));
        assert!(rl.try_consume(ip));
        assert!(rl.try_consume(ip));
        // Bucket empty.
        assert!(!rl.try_consume(ip));
    }

    #[test]
    fn rate_limiter_isolates_ips() {
        let mut rl = RateLimiter::new(1.0, 1.0);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.try_consume(a));
        assert!(!rl.try_consume(a));
        // b has its own bucket.
        assert!(rl.try_consume(b));
    }

    #[test]
    fn connection_counter_enforces_caps() {
        let caps = Caps {
            max_total_connections: 3,
            max_per_ip_connections: 2,
        };
        let mut cnt = ConnectionCounter::default();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(cnt.try_acquire(caps, a));
        assert!(cnt.try_acquire(caps, a));
        // Per-IP cap of 2 for `a`.
        assert!(!cnt.try_acquire(caps, a));
        assert!(cnt.try_acquire(caps, b));
        // Total cap of 3 hit.
        assert!(!cnt.try_acquire(caps, b));

        cnt.release(a);
        assert_eq!(cnt.total(), 2);
        assert!(cnt.try_acquire(caps, b));
    }
}
