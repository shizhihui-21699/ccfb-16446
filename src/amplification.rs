//! Anti-amplification accounting.
//!
//! A server must never send more bytes toward a peer than it can justify by
//! bytes the peer actually sent from that address.  Otherwise a small spoofed
//! handshake (say 1200 bytes) becomes a large reflection: the attacker sets the
//! source address of a victim and the server blasts the victim with TLS
//! certificates, stream data or handshake rejects.
//!
//! # The credit model
//!
//! Accounting is explicit and post-hoc, mirroring how a real datagram stack
//! works:
//!
//! * [`AddressAmplificationGuard::on_receive`] records bytes that arrived from
//!   an address.  Received bytes are what earn send allowance.
//! * [`AddressAmplificationGuard::try_send`] / [`AddressAmplificationGuard::send`]
//!   record bytes actually transmitted and fail when allowance is exhausted.
//!
//! At any moment the allowance toward an address is
//!
//! ```text
//! allowance = min(received × credit_factor, cap(tier)) + granted(tier) − sent
//! ```
//!
//! clamped at zero, where `tier` is the strongest proof the peer has given
//! (see [`AntiAmplificationConfig`]).  The `granted` bootstrap is handed out at most once per
//! tier, so replaying a token or re-validating a path cannot reset spend.
//!
//! To make a forgotten send report *fail safe* rather than fail open, the
//! [`crate::server`] layer calls [`AddressAmplificationGuard::reserve`] before
//! authorising a datagram and [`AddressAmplificationGuard::settle`] with the
//! true size afterwards: a forgotten `settle` leaves the reservation spent,
//! which under-sends to a peer, never over-sends.
//!
//! # Address versus path accounting
//!
//! This table is keyed by *address*, which is the right granularity for the
//! stateless handshake path where no connection object exists yet.  An
//! established connection additionally keeps a per-path balance in
//! [`crate::migration`]; both must permit a send for it to go out.

use std::collections::HashMap;

use crate::address::PeerAddress;
use crate::clock::Clock;
use crate::error::AmplificationBlocked;

/// Tunables for the anti-amplification guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiAmplificationConfig {
    /// Multiple of received bytes credited to the sender.  The usual choice
    /// is `3`, mirroring the classic "3×" hop-by-hop limit.
    pub credit_factor: u64,
    /// Ceiling on credited bytes for an address whose reachability has *not*
    /// been proven.  Bounds how much a spoofed address can bank while idle,
    /// and therefore how much a long-lived forged source can later receive.
    pub burst_cap: u64,
    /// Allowance granted the first time an address presents a *valid token*.
    ///
    /// A token (Retry or cached proof) proves the address was reachable when
    /// the token was issued, which is enough to justify a small handshake
    /// burst.  It is deliberately far below [`Self::validated_floor`]: a token
    /// can be presented by anyone who possesses it and can be replayed by the
    /// address it names, so it must not unlock a large reflection surface on
    /// its own.
    pub token_floor: u64,
    /// Allowance granted once a connection is *confirmed* by a full round trip
    /// on the live path (a path-challenge response, or sustained
    /// bidirectional traffic).  This is the only state in which a large
    /// send allowance is safe, because the address has just proven, in real
    /// time, that it can receive and answer.
    pub validated_floor: u64,
    /// Maximum number of per-address tracking entries.
    pub max_addresses: usize,
}

impl Default for AntiAmplificationConfig {
    fn default() -> Self {
        Self {
            credit_factor: 3,
            // An unvalidated source can bank at most 8 KiB of receipts, so a
            // forged handshake reflects at most 24 KiB.
            burst_cap: 8 * 1024,
            // A token gets the peer through the handshake (certificate chain
            // plus a little headroom), not a data flood.
            token_floor: 64 * 1024,
            // Half a megabyte: a *confirmed* peer can receive a burst while it
            // uploads a large body, and the per-path balance still applies.
            validated_floor: 512 * 1024,
            max_addresses: 100_000,
        }
    }
}

impl AntiAmplificationConfig {
    fn validate(&self) -> Result<(), &'static str> {
        if self.credit_factor == 0 {
            return Err("credit_factor must be at least 1");
        }
        if self.burst_cap == 0 {
            return Err("burst_cap must be at least 1");
        }
        if self.token_floor < self.burst_cap {
            return Err("token_floor must be at least burst_cap");
        }
        if self.validated_floor < self.token_floor {
            return Err("validated_floor must be at least token_floor");
        }
        if self.max_addresses == 0 {
            return Err("max_addresses must be at least 1");
        }
        Ok(())
    }
}

/// The ledger for one address.
///
/// Allowance is the sum of two independent grants:
///
/// * `min(received × factor, cap)` — earned by bytes the peer sent, where the
///   cap depends on the peer's strongest proven state (none / token /
///   confirmed); and
/// * `granted` — a one-time bootstrap handed out when the peer first presents
///   a valid token and again, once, when it is confirmed by a live round trip.
///
/// Both are reduced by `sent`.  Each bootstrap is granted at most once, so a
/// peer cannot reset its spend by re-presenting tokens, and the reflection
/// bound holds even under token replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ledger {
    received: u64,
    sent: u64,
    granted: u64,
    factor: u64,
    burst_cap: u64,
    token_cap: u64,
    confirmed_cap: u64,
    /// Strongest state the peer has proven: 0 = none, 1 = token, 2 = confirmed.
    tier: u8,
    last_touched: u64,
}

impl Ledger {
    fn new(factor: u64, burst_cap: u64, token_cap: u64, confirmed_cap: u64, now: u64) -> Self {
        Self {
            received: 0,
            sent: 0,
            granted: 0,
            factor,
            burst_cap,
            token_cap,
            confirmed_cap,
            tier: 0,
            last_touched: now,
        }
    }

    fn cap(&self) -> u64 {
        match self.tier {
            0 => self.burst_cap,
            1 => self.token_cap,
            _ => self.confirmed_cap,
        }
    }

    fn receipt_credit(&self) -> u64 {
        self.received.saturating_mul(self.factor).min(self.cap())
    }

    fn credited(&self) -> u64 {
        self.receipt_credit().saturating_add(self.granted)
    }

    fn available(&self) -> u64 {
        self.credited().saturating_sub(self.sent)
    }

    fn try_send(&mut self, n: u64) -> bool {
        if n <= self.available() {
            self.sent = self.sent.saturating_add(n);
            true
        } else {
            false
        }
    }

    fn refund(&mut self, n: u64) {
        self.sent = self.sent.saturating_sub(n);
    }

    /// Advance to (at most) `tier`, granting a one-time bootstrap sufficient to
    /// bring allowance up to `floor`.  Re-entering an already-reached tier is a
    /// no-op, so a peer cannot reset its spend by repeating the proof.
    fn advance(&mut self, tier: u8, floor: u64) {
        if tier <= self.tier {
            return;
        }
        self.tier = tier;
        let shortfall = floor.saturating_sub(self.available());
        self.granted = self.granted.saturating_add(shortfall);
    }
}

/// Per-address anti-amplification ledger.
#[derive(Debug)]
pub struct AddressAmplificationGuard {
    entries: HashMap<PeerAddress, Ledger>,
    config: AntiAmplificationConfig,
    clock: Box<dyn Clock>,
}

impl AddressAmplificationGuard {
    /// Create a guard with the given policy.
    ///
    /// # Panics
    /// Panics if the configuration is invalid; use
    /// [`Self::try_new`] to handle that as an error.
    pub fn new(config: AntiAmplificationConfig, clock: impl Clock + 'static) -> Self {
        Self::try_new(config, clock).expect("valid anti-amplification configuration")
    }

    /// Fallible constructor validating the configuration.
    pub fn try_new(
        config: AntiAmplificationConfig,
        clock: impl Clock + 'static,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            entries: HashMap::new(),
            config,
            clock: Box::new(clock),
        })
    }

    /// Policy in force.
    pub fn config(&self) -> AntiAmplificationConfig {
        self.config
    }

    /// Record `received` bytes from `peer`.
    pub fn on_receive(&mut self, peer: PeerAddress, received: u64) {
        let now = self.clock.unix_secs();
        if !self.entries.contains_key(&peer) && self.entries.len() >= self.config.max_addresses {
            self.evict_one();
        }
        let fresh = self.fresh_ledger(now);
        let entry = self.entries.entry(peer).or_insert(fresh);
        entry.received = entry.received.saturating_add(received);
        entry.last_touched = now;
    }

    /// Bytes that may still be sent toward `peer` right now.
    pub fn available(&self, peer: PeerAddress) -> u64 {
        self.entries.get(&peer).map(Ledger::available).unwrap_or(0)
    }

    /// Record a send of `n` bytes toward `peer`.  Returns `false` if the
    /// allowance did not cover it, in which case nothing is recorded — the
    /// caller must not have sent.
    pub fn try_send(&mut self, peer: PeerAddress, n: u64) -> bool {
        let now = self.clock.unix_secs();
        match self.entries.get_mut(&peer) {
            Some(entry) => {
                entry.last_touched = now;
                entry.try_send(n)
            }
            // Sending zero bytes to an unknown address is a no-op.
            None => n == 0,
        }
    }

    /// Record a send of `n` bytes, or return the shortfall.
    pub fn send(&mut self, peer: PeerAddress, n: u64) -> Result<(), AmplificationBlocked> {
        let available = self.available(peer);
        if self.try_send(peer, n) {
            Ok(())
        } else {
            Err(AmplificationBlocked {
                requested: n,
                available,
            })
        }
    }

    /// Reserve `n` bytes of allowance before authorising a datagram, so a
    /// forgotten [`Self::settle`] cannot amplify.  Reservation is implemented
    /// as a send of the maximum size; [`Self::settle`] refunds the unused part.
    pub fn reserve(&mut self, peer: PeerAddress, n: u64) -> Result<(), AmplificationBlocked> {
        self.send(peer, n)
    }

    /// Settle a previous reservation of `reserved` bytes when only `actual`
    /// were sent.  If `actual` exceeds `reserved`, the excess is charged too.
    ///
    /// Returns `false` if the excess could not be covered (a caller bug).
    pub fn settle(&mut self, peer: PeerAddress, reserved: u64, actual: u64) -> bool {
        if actual <= reserved {
            if let Some(entry) = self.entries.get_mut(&peer) {
                entry.refund(reserved - actual);
            }
            true
        } else {
            let extra = actual - reserved;
            self.try_send(peer, extra)
        }
    }

    /// Record that `peer` presented a valid address token (a Retry token or a
    /// cached address proof).  Raises the peer to the *token* tier: enough to
    /// complete a handshake, not enough to flood.
    ///
    /// A token is bound to an address and proves that address was reachable
    /// when the token was issued, but the same token can be presented by
    /// anyone holding it and replayed by the address it names.  It therefore
    /// grants a strictly smaller allowance than [`Self::confirm`].
    pub fn grant_for_token(&mut self, peer: PeerAddress) {
        self.advance(peer, 1, self.config.token_floor);
    }

    /// Record that `peer` completed a live round trip (a path-challenge echo,
    /// or equivalent proof of real-time reachability).  Raises the peer to the
    /// *confirmed* tier, the only state in which a large send allowance is
    /// granted.
    pub fn confirm(&mut self, peer: PeerAddress) {
        self.advance(peer, 2, self.config.validated_floor);
    }

    fn advance(&mut self, peer: PeerAddress, tier: u8, floor: u64) {
        let now = self.clock.unix_secs();
        if !self.entries.contains_key(&peer) {
            if self.entries.len() >= self.config.max_addresses {
                self.evict_one();
            }
            let ledger = self.fresh_ledger(now);
            self.entries.insert(peer, ledger);
        }
        if let Some(entry) = self.entries.get_mut(&peer) {
            entry.advance(tier, floor);
            entry.last_touched = now;
        }
    }

    /// Forget a peer entirely.  Its next packet is treated as a cold start.
    pub fn forget(&mut self, peer: PeerAddress) {
        self.entries.remove(&peer);
    }

    /// Number of tracked addresses.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no addresses are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries untouched for at least `older_than_secs`.
    pub fn sweep(&mut self, older_than_secs: u64) {
        let now = self.clock.unix_secs();
        self.entries
            .retain(|_, e| now.saturating_sub(e.last_touched) < older_than_secs);
    }

    fn fresh_ledger(&self, now: u64) -> Ledger {
        Ledger::new(
            self.config.credit_factor,
            self.config.burst_cap,
            self.config.token_floor,
            self.config.validated_floor,
            now,
        )
    }

    fn evict_one(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_touched)
            .map(|(k, _)| *k)
        {
            self.entries.remove(&oldest);
        }
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

    fn peer() -> PeerAddress {
        PeerAddress::v4("198.51.100.10".parse().unwrap(), 1234)
    }

    fn guard(config: AntiAmplificationConfig) -> AddressAmplificationGuard {
        AddressAmplificationGuard::new(config, ArcClock(Arc::new(ManualClock::new(0))))
    }

    #[test]
    fn credit_multiplier_holds() {
        let mut g = guard(AntiAmplificationConfig::default());
        g.on_receive(peer(), 100);
        assert_eq!(g.available(peer()), 300);
        assert!(g.try_send(peer(), 300));
        assert!(!g.try_send(peer(), 1));
        // A refused send records nothing.
        g.on_receive(peer(), 10);
        let before = g.available(peer());
        let err = g.send(peer(), 1_000_000).unwrap_err();
        assert_eq!(err.available, before);
        assert_eq!(g.available(peer()), before);
    }

    #[test]
    fn credited_amount_is_capped() {
        let mut g = guard(AntiAmplificationConfig {
            burst_cap: 1_000,
            ..Default::default()
        });
        g.on_receive(peer(), 100_000);
        assert_eq!(g.available(peer()), 1_000);
    }

    #[test]
    fn unknown_address_has_no_credit() {
        let mut g = guard(AntiAmplificationConfig::default());
        assert_eq!(g.available(peer()), 0);
        assert!(!g.try_send(peer(), 1));
        assert!(g.send(peer(), 1).is_err());
        assert!(g.try_send(peer(), 0), "zero-byte send is always allowed");
    }

    #[test]
    fn receiving_grants_proportional_send_credit() {
        let mut g = guard(AntiAmplificationConfig::default());
        g.on_receive(peer(), 1200);
        assert_eq!(g.available(peer()), 3600);
        assert!(g.send(peer(), 3600).is_ok());
        assert_eq!(g.available(peer()), 0);
        assert!(g.send(peer(), 1).is_err());
    }

    fn tiered_config() -> AntiAmplificationConfig {
        AntiAmplificationConfig {
            burst_cap: 1_000,
            token_floor: 5_000,
            validated_floor: 10_000,
            ..Default::default()
        }
    }

    #[test]
    fn each_tier_grants_its_floor_once() {
        let mut g = guard(tiered_config());
        g.on_receive(peer(), 100); // 300 credited while unvalidated
        assert_eq!(g.available(peer()), 300);

        // A valid token: enough to finish a handshake.
        g.grant_for_token(peer());
        assert_eq!(g.available(peer()), 5_000);

        // Re-presenting a token cannot reset spend.
        assert!(g.try_send(peer(), 5_000));
        assert_eq!(g.available(peer()), 0);
        g.grant_for_token(peer());
        assert_eq!(g.available(peer()), 0, "replayed token must not refill");

        // A live round trip confirms the peer and unlocks the data floor.
        g.confirm(peer());
        assert_eq!(g.available(peer()), 10_000);
        // Confirming again does not refill.
        assert!(g.try_send(peer(), 10_000));
        g.confirm(peer());
        assert_eq!(g.available(peer()), 0);
        g.on_receive(peer(), 100);
        assert_eq!(g.available(peer()), 300);
    }

    #[test]
    fn receipts_are_capped_by_current_tier() {
        let mut g = guard(tiered_config());
        // Unvalidated receipts are capped at burst_cap (1_000).
        g.on_receive(peer(), 10_000_000);
        assert_eq!(g.available(peer()), 1_000);
        // Token tier raises the cap to token_floor (5_000).
        g.grant_for_token(peer());
        assert_eq!(g.available(peer()), 5_000);
        // Confirmed tier raises it to validated_floor (10_000).
        g.confirm(peer());
        assert_eq!(g.available(peer()), 10_000);
        // Further receipts cannot exceed the confirmed cap.
        g.on_receive(peer(), 10_000_000);
        assert_eq!(g.available(peer()), 10_000);
    }

    #[test]
    fn tier_floors_must_be_ordered() {
        // token_floor below burst_cap is a configuration error.
        assert!(AddressAmplificationGuard::try_new(
            AntiAmplificationConfig {
                burst_cap: 1000,
                token_floor: 999,
                validated_floor: 10_000,
                ..Default::default()
            },
            ArcClock(Arc::new(ManualClock::new(0)))
        )
        .is_err());
        // validated_floor below token_floor is likewise an error.
        assert!(AddressAmplificationGuard::try_new(
            AntiAmplificationConfig {
                burst_cap: 1000,
                token_floor: 5_000,
                validated_floor: 4_999,
                ..Default::default()
            },
            ArcClock(Arc::new(ManualClock::new(0)))
        )
        .is_err());
    }

    #[test]
    fn token_floor_applies_to_unseen_address() {
        let mut g = guard(tiered_config());
        g.grant_for_token(peer());
        assert_eq!(g.available(peer()), 5_000);
        g.forget(peer());
        g.confirm(peer());
        assert_eq!(g.available(peer()), 10_000);
    }

    #[test]
    fn reserve_then_settle_refunds_unused() {
        let mut g = guard(AntiAmplificationConfig::default());
        g.on_receive(peer(), 1000); // 3000 credited
        assert!(g.reserve(peer(), 3000).is_ok());
        assert_eq!(g.available(peer()), 0);
        assert!(g.settle(peer(), 3000, 1200));
        assert_eq!(g.available(peer()), 1800);
    }

    #[test]
    fn forgotten_settle_is_conservative() {
        let mut g = guard(AntiAmplificationConfig::default());
        g.on_receive(peer(), 1000);
        assert!(g.reserve(peer(), 3000).is_ok());
        // Caller forgets to settle: allowance stays spent, never over-granted.
        assert_eq!(g.available(peer()), 0);
    }

    #[test]
    fn table_sheds_entries_when_full() {
        let clock = Arc::new(ManualClock::new(0));
        let mut g = AddressAmplificationGuard::new(
            AntiAmplificationConfig {
                max_addresses: 2,
                ..Default::default()
            },
            ArcClock(clock.clone()),
        );
        let a = PeerAddress::v4("10.0.0.1".parse().unwrap(), 1);
        let b = PeerAddress::v4("10.0.0.2".parse().unwrap(), 1);
        let c = PeerAddress::v4("10.0.0.3".parse().unwrap(), 1);
        g.on_receive(a, 100);
        clock.advance(1);
        g.on_receive(b, 100);
        clock.advance(1);
        g.on_receive(c, 100);
        assert_eq!(g.len(), 2);
        assert_eq!(g.available(a), 0, "least recently touched entry evicted");
        assert_eq!(g.available(c), 300);
    }

    #[test]
    fn forged_source_cannot_amplify() {
        let mut g = guard(AntiAmplificationConfig::default());
        let victim = PeerAddress::v4("203.0.113.66".parse().unwrap(), 9999);
        g.on_receive(victim, 1200);
        for _ in 0..3 {
            assert!(g.send(victim, 1200).is_ok());
        }
        assert!(g.send(victim, 1200).is_err(), "no amplification beyond 3x");
    }

    #[test]
    fn sweep_drops_stale_entries() {
        let clock = Arc::new(ManualClock::new(0));
        let mut g = AddressAmplificationGuard::new(
            AntiAmplificationConfig::default(),
            ArcClock(clock.clone()),
        );
        g.on_receive(peer(), 100);
        clock.advance(120);
        g.sweep(60);
        assert!(g.is_empty());
    }

    #[test]
    fn rejects_invalid_config() {
        assert!(AddressAmplificationGuard::try_new(
            AntiAmplificationConfig {
                credit_factor: 0,
                ..Default::default()
            },
            ArcClock(Arc::new(ManualClock::new(0)))
        )
        .is_err());
    }
}
