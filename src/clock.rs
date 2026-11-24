//! Time source abstraction.
//!
//! Every stateful security component takes its notion of time from a [`Clock`]
//! rather than calling `SystemTime::now()` directly.  This keeps token
//! lifetime, anti-amplification credit and path-validation backoff fully
//! deterministic in tests, and lets a server share a single (possibly
//! coarsened) clock across components.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time, in whole seconds since the Unix epoch.
///
/// Implementations must be cheap and thread-safe: they are called on packet
/// processing paths.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Seconds since the Unix epoch.
    fn unix_secs(&self) -> u64;
}

/// Reads the host wall clock.  Cluster members must keep their clocks within
/// the configured token skew budget (see [`crate::token::TokenConfig::max_clock_skew_secs`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A manually advanced clock for deterministic tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    secs: AtomicU64,
}

impl ManualClock {
    /// Create a clock frozen at `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        Self {
            secs: AtomicU64::new(unix_secs),
        }
    }

    /// Advance the clock by `delta` seconds.
    pub fn advance(&self, delta: u64) {
        self.secs.fetch_add(delta, Ordering::SeqCst);
    }

    /// Set the clock to an absolute Unix time.
    pub fn set(&self, unix_secs: u64) {
        self.secs.store(unix_secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_secs(&self) -> u64 {
        self.secs.load(Ordering::SeqCst)
    }
}

/// A clock handle that can be cloned and shared between components.
///
/// `Arc<dyn Clock>` itself implements [`Clock`], so any component accepting
/// `impl Clock + 'static` (including ones that box their clock) can be handed
/// a clone and will observe the same time source.  Tests use this to drive a
/// single [`ManualClock`] across a whole [`crate::server::Server`].
pub type SharedClock = std::sync::Arc<dyn Clock>;

impl Clock for std::sync::Arc<dyn Clock> {
    fn unix_secs(&self) -> u64 {
        (**self).unix_secs()
    }
}
