//! Connection-count caps and request rate limiting.
//!
//! The rate limiter is a per-IP token bucket sized in requests per second.
//! Connection caps are enforced on accept; once at the limit, new Initial
//! packets are silently dropped (cheaper than answering with a
//! CONNECTION_CLOSE that the peer might just retry forever).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Key both rate-limiting and connection-cap buckets on a /32 IPv4
/// or /64 IPv6 prefix (#118). A residential IPv6 allocation is
/// typically /56 or /64; without this masking an attacker can
/// trivially rotate through 2^64 source addresses to evade both
/// counters. IPv4 stays full-precision because each address is a
/// precious shared resource and false-sharing inside a single /24
/// would be too aggressive for the common-deployment case
/// (corporate NATs, mobile networks).
fn bucket_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            for b in &mut o[8..] {
                *b = 0;
            }
            o
        }
    }
}

type IpKey = [u8; 16];

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

/// A token-bucket rate limiter keyed by IP prefix (see [`bucket_key`]).
/// Refills at `rps` tokens per second, up to `burst` capacity. Calling
/// `try_consume` returns false if no token is available.
pub struct RateLimiter {
    rps: f64,
    burst: f64,
    buckets: HashMap<IpKey, Bucket>,
    /// Hard cap on the number of distinct IP buckets we will track at
    /// once. On overflow the least-recently-used bucket is dropped
    /// (#121), so an attacker who fills the table just under the
    /// idle threshold cannot poison it indefinitely.
    max_tracked: usize,
    /// Run a periodic sweep at most this often. Combined with the
    /// at-capacity LRU eviction, this keeps the table tight even if
    /// it doesn't reach `max_tracked` (#121).
    sweep_interval: Duration,
    last_sweep: Instant,
    idle_cutoff: Duration,
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
            sweep_interval: Duration::from_secs(60),
            last_sweep: Instant::now(),
            idle_cutoff: Duration::from_secs(300),
        }
    }

    pub fn try_consume(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let key = bucket_key(ip);
        self.maybe_sweep(now);
        self.make_room_for(&key, now);
        let bucket = self.buckets.entry(key).or_insert(Bucket {
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

    /// #121: sweep stale entries on a fixed cadence (not just at
    /// capacity), so an attacker can't pin the table at ~max-1 with
    /// refreshes timed just under idle_cutoff.
    fn maybe_sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) < self.sweep_interval {
            return;
        }
        self.last_sweep = now;
        let cutoff = self.idle_cutoff;
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last) < cutoff);
    }

    /// #121: when at capacity, drop the single least-recently-used
    /// entry to make room for the new one rather than refusing the
    /// insert. Bounded memory, fair-ish under attack.
    fn make_room_for(&mut self, key: &IpKey, _now: Instant) {
        if self.buckets.len() < self.max_tracked {
            return;
        }
        if self.buckets.contains_key(key) {
            return;
        }
        if let Some(oldest_key) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last)
            .map(|(k, _)| *k)
        {
            self.buckets.remove(&oldest_key);
        }
    }
}

/// Tracker for the per-IP and global concurrent-connection caps.
/// Keyed on the /32 (IPv4) or /64 (IPv6) prefix (#118) so a single
/// host can't trivially evade the per-IP cap by rotating source
/// addresses within its allocation.
#[derive(Default)]
pub struct ConnectionCounter {
    total: usize,
    per_ip: HashMap<IpKey, usize>,
}

impl ConnectionCounter {
    pub fn try_acquire(&mut self, caps: Caps, ip: IpAddr) -> bool {
        if self.total >= caps.max_total_connections {
            return false;
        }
        let key = bucket_key(ip);
        let entry = self.per_ip.entry(key).or_insert(0);
        if *entry >= caps.max_per_ip_connections {
            return false;
        }
        *entry += 1;
        self.total += 1;
        true
    }

    pub fn release(&mut self, ip: IpAddr) {
        self.total = self.total.saturating_sub(1);
        let key = bucket_key(ip);
        if let Some(c) = self.per_ip.get_mut(&key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_ip.remove(&key);
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv6_prefix_keys_collapse_to_slash_64() {
        // #118: two addresses in the same /64 should share a bucket
        // so an attacker rotating through the suffix can't bypass.
        let a = IpAddr::V6("2001:db8:1234:5678::1".parse().unwrap());
        let b = IpAddr::V6("2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap());
        assert_eq!(bucket_key(a), bucket_key(b));
        // A neighbouring /64 keys differently.
        let c = IpAddr::V6("2001:db8:1234:5679::1".parse().unwrap());
        assert_ne!(bucket_key(a), bucket_key(c));
    }

    #[test]
    fn ipv4_addresses_keep_full_precision() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_ne!(bucket_key(a), bucket_key(b));
    }

    #[test]
    fn ipv6_rate_limit_shared_across_slash_64() {
        // #118: per-IP rate limit must apply across a whole /64.
        let mut rl = RateLimiter::new(1.0, 1.0);
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2));
        assert!(rl.try_consume(a));
        // b is a different /128 but shares the /64 — bucket is
        // exhausted, must be refused.
        assert!(!rl.try_consume(b));
    }

    #[test]
    fn lru_eviction_at_capacity_keeps_inserting() {
        // #121: at max_tracked, the oldest idle bucket is dropped so
        // a fresh source can still get in. Pre-fix this returned
        // "false" / refused new entries when full.
        let mut rl = RateLimiter::new(1000.0, 1000.0);
        rl.max_tracked = 2;
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(rl.try_consume(a));
        std::thread::sleep(Duration::from_millis(2));
        assert!(rl.try_consume(b));
        std::thread::sleep(Duration::from_millis(2));
        // c hits capacity; LRU (a) should be evicted, c inserted.
        assert!(rl.try_consume(c));
        assert_eq!(rl.buckets.len(), 2);
        // The oldest (a) was the one dropped.
        assert!(!rl.buckets.contains_key(&bucket_key(a)));
        assert!(rl.buckets.contains_key(&bucket_key(b)));
        assert!(rl.buckets.contains_key(&bucket_key(c)));
    }

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
