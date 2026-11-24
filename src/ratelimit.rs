//! Token-bucket rate limiting shared by several security components.
//!
//! The limiter is deliberately allocation-free per call and operates in
//! *seconds*, matching the granularity of the rest of the crate.  Buckets are
//! kept in a caller-owned map and swept opportunistically, so an attacker who
//! sprays spoofed addresses cannot grow memory without bound: a sweep is
//! forced whenever the map exceeds its cap.

use std::collections::HashMap;
use std::hash::Hash;

use crate::clock::Clock;

/// A token bucket allowing `capacity` events, refilled at `refill_per_sec`
/// events per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucket {
    capacity: u32,
    refill_per_sec: u32,
    tokens: u32,
    last_refill: u64,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(capacity: u32, refill_per_sec: u32, now: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            refill_per_sec,
            tokens: capacity.max(1),
            last_refill: now,
        }
    }

    /// Attempt to take one token, refilling first.
    pub fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Take up to `n` tokens, returning how many were available.
    pub fn take(&mut self, n: u32, now: u64) -> u32 {
        self.refill(now);
        let granted = n.min(self.tokens);
        self.tokens -= granted;
        granted
    }

    /// Tokens currently available (after refilling to `now`).
    pub fn available(&mut self, now: u64) -> u32 {
        self.refill(now);
        self.tokens
    }

    /// Seconds until at least one token is available, or zero if one is.
    pub fn secs_until_available(&mut self, now: u64) -> u64 {
        self.refill(now);
        if self.tokens > 0 || self.refill_per_sec == 0 {
            return 0;
        }
        // Ceil division: 1 token needs `1/rate` seconds.
        (1u64).div_ceil(self.refill_per_sec as u64)
    }

    /// Whether the bucket has gone fully idle and can be collected.
    pub fn is_idle(&mut self, now: u64) -> bool {
        self.refill(now);
        self.tokens == self.capacity
    }

    fn refill(&mut self, now: u64) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now - self.last_refill;
        let gained = elapsed.saturating_mul(self.refill_per_sec as u64);
        self.tokens = self
            .tokens
            .saturating_add(gained.min(u32::MAX as u64) as u32)
            .min(self.capacity);
        self.last_refill = now;
    }
}

/// A map of token buckets with a hard entry cap.
///
/// When the map is full, inserting a new key first sweeps entries that have
/// fully refilled (i.e. went idle).  If nothing can be evicted the insertion is
/// refused, which is the safe direction: the limiter becomes *stricter*, never
/// looser, under memory pressure.
#[derive(Debug)]
pub struct BucketTable<K> {
    buckets: HashMap<K, TokenBucket>,
    capacity: u32,
    refill_per_sec: u32,
    max_entries: usize,
}

impl<K: Eq + Hash + Clone> BucketTable<K> {
    /// Create a table whose buckets allow `capacity` events refilling at
    /// `refill_per_sec`, holding at most `max_entries` keys.
    pub fn new(capacity: u32, refill_per_sec: u32, max_entries: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_per_sec,
            max_entries: max_entries.max(1),
        }
    }

    /// Try to take one token for `key`.
    ///
    /// Returns `false` if the bucket is empty *or* if the table is full and
    /// the key is new and nothing could be swept.  Both are refusals.
    pub fn try_take(&mut self, key: &K, now: u64) -> bool {
        if let Some(bucket) = self.buckets.get_mut(key) {
            return bucket.try_take(now);
        }
        if self.buckets.len() >= self.max_entries {
            self.sweep(now);
            if self.buckets.len() >= self.max_entries {
                return false;
            }
        }
        let mut bucket = TokenBucket::new(self.capacity, self.refill_per_sec, now);
        let granted = bucket.try_take(now);
        self.buckets.insert(key.clone(), bucket);
        granted
    }

    /// Current bucket for `key`, if present.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut TokenBucket> {
        self.buckets.get_mut(key)
    }

    /// Remove a key's bucket.
    pub fn remove(&mut self, key: &K) -> Option<TokenBucket> {
        self.buckets.remove(key)
    }

    /// Number of live buckets.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether the table holds no buckets.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Drop buckets that have fully refilled.
    pub fn sweep(&mut self, now: u64) {
        self.buckets.retain(|_, bucket| !bucket.is_idle(now));
    }

    /// Drop every bucket.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

/// Convenience wrapper that ties a [`BucketTable`] to a [`Clock`].
#[derive(Debug)]
pub struct RateLimiter<K> {
    table: BucketTable<K>,
    clock: Box<dyn Clock>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    /// See [`BucketTable::new`].
    pub fn new(
        capacity: u32,
        refill_per_sec: u32,
        max_entries: usize,
        clock: impl Clock + 'static,
    ) -> Self {
        Self {
            table: BucketTable::new(capacity, refill_per_sec, max_entries),
            clock: Box::new(clock),
        }
    }

    /// Try to take one token for `key` at the current time.
    pub fn try_take(&mut self, key: &K) -> bool {
        let now = self.clock.unix_secs();
        self.table.try_take(key, now)
    }

    /// Access the underlying table.
    pub fn table_mut(&mut self) -> &mut BucketTable<K> {
        &mut self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use std::sync::Arc;

    struct ArcClock(Arc<ManualClock>);
    impl std::fmt::Debug for ArcClock {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ArcClock")
        }
    }
    impl Clock for ArcClock {
        fn unix_secs(&self) -> u64 {
            self.0.unix_secs()
        }
    }

    #[test]
    fn bucket_drains_and_refills() {
        let mut b = TokenBucket::new(3, 1, 100);
        assert!(b.try_take(100));
        assert!(b.try_take(100));
        assert!(b.try_take(100));
        assert!(!b.try_take(100));
        // One second later exactly one token has refilled.
        assert_eq!(b.secs_until_available(101), 0);
        assert!(b.try_take(101));
        assert!(!b.try_take(101));
        assert_eq!(b.secs_until_available(101), 1);
        assert_eq!(b.secs_until_available(102), 0);
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut b = TokenBucket::new(5, 100, 0);
        assert!(b.is_idle(0));
        b.try_take(0);
        assert!(!b.is_idle(0));
        assert!(b.is_idle(1));
    }

    #[test]
    fn table_evicts_idle_buckets_before_refusing() {
        let mut t = BucketTable::new(10, 10, 2);
        assert!(t.try_take(&1u32, 100));
        assert!(t.try_take(&2u32, 100));
        // New key while full and nothing idle: refused.
        assert!(!t.try_take(&3u32, 100));
        assert_eq!(t.len(), 2);
        // Eventually the old buckets refill and can be swept.
        // Buckets are full (capacity 10) the instant they are created except
        // for the one token taken, so after refill they are idle.
        assert!(t.try_take(&3u32, 101));
    }

    #[test]
    fn rate_limiter_uses_clock() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut limiter = RateLimiter::new(2, 1, 100, ArcClock(clock.clone()));
        assert!(limiter.try_take(&"a"));
        assert!(limiter.try_take(&"a"));
        assert!(!limiter.try_take(&"a"));
        clock.advance(1);
        assert!(limiter.try_take(&"a"));
    }

    #[test]
    fn zero_capacity_still_allows_one() {
        // A misconfigured 0 is clamped to 1 rather than deadlocking the
        // limiter; strictness is preserved by the refill rate.
        let mut b = TokenBucket::new(0, 1, 0);
        assert!(b.try_take(0));
        assert!(!b.try_take(0));
    }
}
