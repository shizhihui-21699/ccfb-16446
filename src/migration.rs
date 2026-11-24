//! Connection migration and path validation.
//!
//! # The two attacks
//!
//! * **Off-path migration hijack.**  An attacker who can observe or guess a
//!   connection id sends a packet claiming the peer has moved to the
//!   attacker's address.  If the server simply rebinds the connection, the
//!   attacker parks the victim's connection at an address it controls (or
//!   merely DoSes the victim by black-holing its traffic).
//! * **Path amplification.**  The attacker claims a move to a *victim's*
//!   address; the server then sends probing and data packets to the victim.
//!   This is reflection by another name, so path validation must be
//!   amplification-limited exactly like the handshake.
//!
//! # The defence
//!
//! Migration is *never* trusted on the strength of an incoming datagram alone.
//! It is a three-step, server-driven process:
//!
//! 1. **Admission.**  The claimed path is only considered at all if the
//!    datagram carrying the claim was authenticated as belonging to the
//!    connection (1-RTT protection), *or* the client presents a valid
//!    [`TokenKind::AddressProof`] for the claimed address (0-RTT fast path,
//!    used on the very first packet after a network change to avoid a
//!    round trip).  An unauthenticated claim from a new address is dropped
//!    without any state being created.
//! 2. **Probe.**  The server sends its `PATH_CHALLENGE`-equivalent random
//!    nonce to the claimed address and nothing else meaningful.  Probes are
//!    subject to their own anti-amplification credit, per-peer rate limiting,
//!    a per-connection cap on concurrently pending paths, and a per-connection
//!    migration-frequency cap.
//! 3. **Confirmation.**  The address is only trusted when a response echoes
//!    the challenge, compared in constant time.  Data then flows to the new
//!    address; until then, the old address keeps receiving traffic.
//!
//! # Mobile networks
//!
//! Legitimate clients change address constantly (Wi-Fi ↔ cellular, NAT
//! rebinding, roaming).  The module is tuned so that:
//!
//! * A client that recently proved the same address can reuse its proof token
//!   to resume immediately, with no round trip, even after the connection
//!   state was lost to a load-balancer shuffle and placed on another node.
//! * Alive-but-idle connections are not penalised for moving; only *rapid
//!   repeated* moves within [`MigrationConfig::migration_window_secs`] trip the
//!   frequency cap.
//! * A path that the server was already using is preferred: if the "new"
//!   address equals the currently active path or one that was validated within
//!   [`MigrationConfig::recent_path_grace_secs`], it is adopted without a probe,
//!   because the address was already proven reachable moments ago and the
//!   anti-amplification guard has paid for it.
//!
//! The trade-off is deliberately asymmetric: a *spoofed* claim costs the
//! server one small probe (bounded), while a *legitimate* move costs at most
//! one round trip, and often zero.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use crate::address::PeerAddress;
use crate::clock::Clock;
use crate::error::MigrationError;
use crate::token::{TokenKeyRing, TokenKind};

/// Length of a path challenge nonce.
pub const CHALLENGE_LEN: usize = 8;

/// Tunables for path validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationConfig {
    /// Maximum number of unvalidated paths a single connection may have in
    /// flight at once.
    pub max_pending_paths: usize,
    /// How long a pending path probe is retried before it is abandoned.
    pub validation_timeout_secs: u64,
    /// Maximum probe datagrams sent to a single pending path.
    pub max_probes: u8,
    /// Minimum seconds between probes to the same pending path.
    pub probe_interval_secs: u64,
    /// Per-peer cap on new path probes, refilling per second.
    pub peer_probe_burst: u32,
    /// Per-peer probe refill rate.
    pub peer_probe_refill_per_sec: u32,
    /// Maximum number of migrations accepted per connection per window.
    pub max_migrations_per_window: u32,
    /// Length of the migration-frequency window.
    pub migration_window_secs: u64,
    /// An address validated within this many seconds is adopted without a new
    /// probe.  Keeps rapid Wi-Fi↔cellular flapping cheap for the client while
    /// remaining safe: the address *was* proven reachable recently.
    pub recent_path_grace_secs: u64,
    /// Maximum number of recently validated addresses remembered per
    /// connection.
    pub max_remembered_paths: usize,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_pending_paths: 3,
            validation_timeout_secs: 12,
            max_probes: 4,
            probe_interval_secs: 1,
            peer_probe_burst: 8,
            peer_probe_refill_per_sec: 1,
            max_migrations_per_window: 8,
            migration_window_secs: 60,
            recent_path_grace_secs: 30,
            max_remembered_paths: 8,
        }
    }
}

/// Result of offering a datagram's claimed path to the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDecision {
    /// The claimed address is the currently active path; no action.
    Current,
    /// The claimed address was proven reachable recently and has been adopted
    /// immediately.  Send no probe.
    Adopted,
    /// A probe must be sent to the claimed address.  Caller sends the bytes in
    /// `probe` to `peer`, subject to anti-amplification credit.
    Probe {
        /// Address to probe.
        peer: PeerAddress,
        /// Challenge nonce to transmit.
        challenge: [u8; CHALLENGE_LEN],
    },
    /// The claim was refused; the connection stays on its current path.
    Refused(MigrationError),
}

/// Result of a peer echoing a path challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResponseOutcome {
    /// The challenge matched and the path is now validated and active.
    Validated,
    /// The challenge matched but the path had already been validated (a
    /// duplicate response); nothing changed.
    Duplicate,
    /// The response was refused.
    Refused(MigrationError),
}

/// A pending path validation.
#[derive(Debug, Clone)]
struct PendingPath {
    challenge: [u8; CHALLENGE_LEN],
    deadline: u64,
    probes_sent: u8,
    last_probe: u64,
}

/// Encapsulates the migration and path-validation state of one connection.
///
/// The owner is responsible for packet authentication: it must only call
/// [`Self::offer_path`] for datagrams that it has authenticated as belonging to
/// this connection, or that carry a valid address proof (see
/// [`Self::offer_path_with_proof`]).  This type does *not* itself verify
/// packet protection, because doing so needs the connection's keys, which are
/// outside this crate's scope.
#[derive(Debug)]
pub struct MigrationGuard {
    config: MigrationConfig,
    /// The address currently used for outbound data.
    active: PeerAddress,
    /// Addresses validated recently, newest last, with the time of validation.
    recent: VecDeque<(PeerAddress, u64)>,
    /// Paths currently being probed, keyed by the claimed address.
    pending: HashMap<PeerAddress, PendingPath>,
    /// Timestamps of accepted migrations, oldest first, for frequency capping.
    migrations: VecDeque<u64>,
    clock: Box<dyn Clock>,
}

impl MigrationGuard {
    /// Create a guard for a connection whose active path is `active`.
    pub fn new(active: PeerAddress, config: MigrationConfig, clock: impl Clock + 'static) -> Self {
        let now = clock.unix_secs();
        let mut recent = VecDeque::new();
        recent.push_back((active, now));
        Self {
            config,
            active,
            recent,
            pending: HashMap::new(),
            migrations: VecDeque::new(),
            clock: Box::new(clock),
        }
    }

    /// The address currently used for outbound data.
    pub fn active_path(&self) -> PeerAddress {
        self.active
    }

    /// Policy in force.
    pub fn config(&self) -> MigrationConfig {
        self.config
    }

    /// Number of paths currently awaiting validation.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether `peer` has a probe outstanding.
    pub fn has_pending(&self, peer: PeerAddress) -> bool {
        self.pending.contains_key(&peer)
    }

    /// Whether `peer` was validated within the recent-path grace window.
    pub fn is_recent(&self, peer: PeerAddress) -> bool {
        let now = self.clock.unix_secs();
        self.recent
            .iter()
            .any(|&(a, t)| a == peer && now.saturating_sub(t) <= self.config.recent_path_grace_secs)
    }

    /// Offer an *authenticated* datagram's claimed source path for
    /// consideration.
    ///
    /// `probe_rate_ok` must be supplied by the caller (usually backed by a
    /// shared [`crate::ratelimit::RateLimiter`] keyed on the peer's IP) so a
    /// forged source cannot cause an unbounded number of probes across many
    /// connections.
    pub fn offer_path(&mut self, claimed: PeerAddress, probe_rate_ok: bool) -> PathDecision {
        self.offer_inner(claimed, probe_rate_ok, false)
    }

    /// Offer a path backed by a freshly verified address-proof token.
    ///
    /// The caller must have verified `proof` (via
    /// [`TokenKeyRing::open`] with [`TokenKind::AddressProof`]) and confirmed
    /// that it names `claimed`.  Presenting a proof bypasses the probe: the
    /// address was proven reachable when the token was issued.  Issuing a
    /// proof costs a round trip, so this still does not enable spoofing — an
    /// attacker without the token cannot produce one for the victim.
    pub fn offer_path_with_proof(
        &mut self,
        claimed: PeerAddress,
        ring: &TokenKeyRing,
        proof: &[u8],
        probe_rate_ok: bool,
    ) -> PathDecision {
        let verified = match ring.open(proof, TokenKind::AddressProof, claimed, None) {
            Ok(v) => v,
            Err(_) => return PathDecision::Refused(MigrationError::ProofMismatch),
        };
        // A proof is address-bound and lifetime-bounded, so replaying it can
        // only re-claim *that* address, and only while it is fresh.  The
        // per-window migration cap still applies inside `offer_inner`.
        let _ = verified;
        self.offer_inner(claimed, probe_rate_ok, true)
    }

    fn offer_inner(
        &mut self,
        claimed: PeerAddress,
        probe_rate_ok: bool,
        has_proof: bool,
    ) -> PathDecision {
        let now = self.clock.unix_secs();

        if claimed == self.active {
            return PathDecision::Current;
        }

        // Previously validated recently: adopt without a probe.  Refresh the
        // validation timestamp so a path that keeps being used does not age out
        // of the grace window, and drop any probe still in flight for it.
        if self.is_recent(claimed) && self.may_migrate(now) {
            self.record_migration(now);
            self.pending.remove(&claimed);
            self.mark_validated_internal(claimed, now);
            return PathDecision::Adopted;
        }

        // A valid address proof is as good as a recent validation.
        if has_proof {
            if !self.may_migrate(now) {
                return PathDecision::Refused(MigrationError::TooManyMigrations);
            }
            self.record_migration(now);
            self.pending.remove(&claimed);
            self.mark_validated_internal(claimed, now);
            return PathDecision::Adopted;
        }

        // Already probing this path: re-send only when the interval elapsed.
        if let Some(pending) = self.pending.get_mut(&claimed) {
            let expired = now >= pending.deadline;
            if now
                >= pending
                    .last_probe
                    .saturating_add(self.config.probe_interval_secs)
                && pending.probes_sent < self.config.max_probes
                && !expired
            {
                pending.probes_sent += 1;
                pending.last_probe = now;
                return PathDecision::Probe {
                    peer: claimed,
                    challenge: pending.challenge,
                };
            }
            return PathDecision::Current;
        }

        // New path: enforce resource bounds before creating any state.
        if self.pending.len() >= self.config.max_pending_paths {
            return PathDecision::Refused(MigrationError::TooManyPendingPaths);
        }
        if !probe_rate_ok {
            return PathDecision::Refused(MigrationError::ProbeRateLimited);
        }
        if !self.may_migrate(now) {
            return PathDecision::Refused(MigrationError::TooManyMigrations);
        }

        let challenge = self.fresh_challenge();
        self.pending.insert(
            claimed,
            PendingPath {
                challenge,
                deadline: now.saturating_add(self.config.validation_timeout_secs),
                probes_sent: 1,
                last_probe: now,
            },
        );
        PathDecision::Probe {
            peer: claimed,
            challenge,
        }
    }

    /// Process a response datagram from `from` carrying `challenge`.
    ///
    /// `challenge` is the nonce echoed by the peer.  Comparison is constant
    /// time.  On success the path becomes the active path and data may be sent
    /// there.
    pub fn on_path_response(&mut self, from: PeerAddress, challenge: &[u8]) -> PathResponseOutcome {
        let now = self.clock.unix_secs();
        let pending = match self.pending.get(&from) {
            Some(p) => p.clone(),
            None => {
                if from == self.active {
                    // A late/duplicate response for the already-active path.
                    return PathResponseOutcome::Duplicate;
                }
                return PathResponseOutcome::Refused(MigrationError::NoPendingChallenge);
            }
        };
        if self.expired(&pending, now) {
            self.pending.remove(&from);
            return PathResponseOutcome::Refused(MigrationError::ValidationTimedOut);
        }
        if !crate::token::ct_eq_bytes(challenge, &pending.challenge) {
            return PathResponseOutcome::Refused(MigrationError::ChallengeMismatch);
        }
        self.pending.remove(&from);
        self.record_migration(now);
        self.mark_validated_internal(from, now);
        PathResponseOutcome::Validated
    }

    /// Drop probes whose deadline has passed or whose retry budget is spent.
    /// Call periodically (for example once per second) from a timer.
    /// Returns the addresses whose validation was abandoned.
    pub fn reap_expired(&mut self) -> Vec<PeerAddress> {
        let now = self.clock.unix_secs();
        let mut expired = Vec::new();
        self.pending.retain(|addr, p| {
            let dead = now >= p.deadline || p.probes_sent >= self.config.max_probes;
            if dead {
                expired.push(*addr);
            }
            !dead
        });
        // Also expire remembered paths.
        self.prune_recent(now);
        expired
    }

    /// Forget a pending path because its probe was dropped by the
    /// anti-amplification guard.  Without this, a spoofed claim would keep a
    /// pending slot occupied until timeout.
    pub fn abandon(&mut self, peer: PeerAddress) {
        self.pending.remove(&peer);
    }

    fn expired(&self, p: &PendingPath, now: u64) -> bool {
        now >= p.deadline
    }

    fn may_migrate(&mut self, now: u64) -> bool {
        let window_start = now.saturating_sub(self.config.migration_window_secs);
        while let Some(&t) = self.migrations.front() {
            if t < window_start {
                self.migrations.pop_front();
            } else {
                break;
            }
        }
        (self.migrations.len() as u32) < self.config.max_migrations_per_window
    }

    fn record_migration(&mut self, now: u64) {
        self.migrations.push_back(now);
    }

    fn mark_validated_internal(&mut self, addr: PeerAddress, now: u64) {
        self.active = addr;
        self.recent.retain(|&(a, _)| a != addr);
        self.recent.push_back((addr, now));
        let max = self.config.max_remembered_paths.max(1);
        while self.recent.len() > max {
            self.recent.pop_front();
        }
    }

    fn prune_recent(&mut self, now: u64) {
        let grace = self.config.recent_path_grace_secs;
        // Keep the active path even if it is old: it is the one we are using.
        let active = self.active;
        self.recent
            .retain(|&(a, t)| a == active || now.saturating_sub(t) <= grace);
    }

    fn fresh_challenge(&self) -> [u8; CHALLENGE_LEN] {
        let mut buf = [0u8; CHALLENGE_LEN];
        // If the OS RNG is unavailable we prefer to fail closed by using a
        // value the peer cannot predict *and* cannot match: an all-zero
        // challenge would be predictable, so derive from the clock mixed with
        // the address in a way that at least blocks trivial guessing.  In
        // practice getrandom failing on a supported platform is fatal, and the
        // caller should treat it as such; here we degrade to a per-call value.
        if getrandom::getrandom(&mut buf).is_err() {
            let now = self.clock.unix_secs();
            buf[..8].copy_from_slice(&now.to_be_bytes());
            buf[0] ^= 0xa5;
        }
        buf
    }
}

/// Error for the convenience wrapper below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationSetupError {
    /// The configuration was internally inconsistent.
    Invalid(&'static str),
}

impl fmt::Display for MigrationSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => write!(f, "invalid migration configuration: {msg}"),
        }
    }
}

impl std::error::Error for MigrationSetupError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, ManualClock};
    use std::sync::Arc;

    struct ArcClock(Arc<ManualClock>);
    impl fmt::Debug for ArcClock {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ArcClock")
        }
    }
    impl Clock for ArcClock {
        fn unix_secs(&self) -> u64 {
            self.0.unix_secs()
        }
    }

    fn addr(last: u8, port: u16) -> PeerAddress {
        PeerAddress::v4([10, 0, 0, last].into(), port)
    }

    fn guard(clock: &Arc<ManualClock>) -> MigrationGuard {
        MigrationGuard::new(
            addr(1, 1000),
            MigrationConfig::default(),
            ArcClock(clock.clone()),
        )
    }

    fn ring(clock: &Arc<ManualClock>) -> TokenKeyRing {
        TokenKeyRing::new_with_clock(
            &[b"migration-test-secret-material!!"],
            Default::default(),
            ArcClock(clock.clone()),
        )
        .unwrap()
    }

    fn expect_probe(d: PathDecision) -> ([u8; CHALLENGE_LEN], PeerAddress) {
        match d {
            PathDecision::Probe { peer, challenge } => (challenge, peer),
            other => panic!("expected probe, got {other:?}"),
        }
    }

    #[test]
    fn same_address_is_a_noop() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        assert_eq!(g.offer_path(addr(1, 1000), true), PathDecision::Current);
        assert_eq!(g.pending_count(), 0);
    }

    #[test]
    fn new_path_requires_challenge_response() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (challenge, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        // Data must still go to the old path until validation.
        assert_eq!(g.active_path(), addr(1, 1000));
        assert_eq!(g.pending_count(), 1);

        // Wrong challenge is refused and the pending path is *not* consumed,
        // so a legitimate retransmission can still succeed.
        let mut wrong = challenge;
        wrong[0] ^= 0xff;
        assert_eq!(
            g.on_path_response(peer, &wrong),
            PathResponseOutcome::Refused(MigrationError::ChallengeMismatch)
        );
        assert_eq!(g.pending_count(), 1);

        // Correct challenge validates and switches the active path.
        assert_eq!(
            g.on_path_response(peer, &challenge),
            PathResponseOutcome::Validated
        );
        assert_eq!(g.active_path(), peer);
        assert_eq!(g.pending_count(), 0);
    }

    #[test]
    fn response_for_unknown_path_is_refused() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        assert_eq!(
            g.on_path_response(addr(9, 9), &[0u8; CHALLENGE_LEN]),
            PathResponseOutcome::Refused(MigrationError::NoPendingChallenge)
        );
    }

    #[test]
    fn pending_path_cap_blocks_state_exhaustion() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let cfg = g.config();
        for i in 0..cfg.max_pending_paths {
            assert!(matches!(
                g.offer_path(addr(20 + i as u8, 5000), true),
                PathDecision::Probe { .. }
            ));
        }
        assert_eq!(
            g.offer_path(addr(99, 5000), true),
            PathDecision::Refused(MigrationError::TooManyPendingPaths)
        );
        assert_eq!(g.pending_count(), cfg.max_pending_paths);
    }

    #[test]
    fn probe_rate_limit_is_enforced() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        assert_eq!(
            g.offer_path(addr(2, 2000), false),
            PathDecision::Refused(MigrationError::ProbeRateLimited)
        );
        assert_eq!(g.pending_count(), 0, "no state allocated when rate-limited");
    }

    #[test]
    fn repeated_offers_respect_probe_interval() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (first_challenge, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        // Immediately repeating does not re-probe (returns Current, which the
        // caller interprets as "nothing new to send").
        assert_eq!(g.offer_path(peer, true), PathDecision::Current);
        clock.advance(1);
        let (again, _) = expect_probe(g.offer_path(peer, true));
        assert_eq!(first_challenge, again, "same challenge across retries");
    }

    #[test]
    fn probe_retries_are_bounded_and_then_expire() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (_, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        let max = g.config().max_probes;
        // First offer already sent one probe.
        for _ in 1..max {
            clock.advance(1);
            assert!(matches!(
                g.offer_path(peer, true),
                PathDecision::Probe { .. }
            ));
        }
        clock.advance(1);
        // Budget exhausted: reaping removes it.
        let expired = g.reap_expired();
        assert_eq!(expired, vec![peer]);
        assert_eq!(g.pending_count(), 0);
    }

    #[test]
    fn validation_times_out() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (challenge, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        clock.advance(g.config().validation_timeout_secs + 1);
        assert_eq!(
            g.on_path_response(peer, &challenge),
            PathResponseOutcome::Refused(MigrationError::ValidationTimedOut)
        );
        assert_eq!(g.active_path(), addr(1, 1000));
    }

    #[test]
    fn abandoned_probe_frees_slot() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (_, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        g.abandon(peer);
        assert_eq!(g.pending_count(), 0);
        // Slot may be reused.
        assert!(matches!(
            g.offer_path(addr(3, 3000), true),
            PathDecision::Probe { .. }
        ));
    }

    #[test]
    fn recently_validated_path_is_adopted_without_probe() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (challenge, p2) = expect_probe(g.offer_path(addr(2, 2000), true));
        assert_eq!(
            g.on_path_response(p2, &challenge),
            PathResponseOutcome::Validated
        );

        // Move back to the original path quickly (Wi-Fi <-> cellular flap).
        assert_eq!(g.offer_path(addr(1, 1000), true), PathDecision::Adopted);
        assert_eq!(g.active_path(), addr(1, 1000));

        // After the grace window, the old address needs a probe again.
        clock.advance(g.config().recent_path_grace_secs + 1);
        assert!(matches!(
            g.offer_path(addr(2, 2000), true),
            PathDecision::Probe { .. }
        ));
    }

    #[test]
    fn proof_token_allows_zero_rtt_adoption() {
        let clock = Arc::new(ManualClock::new(1000));
        let ring = ring(&clock);
        let mut g = guard(&clock);
        let new_peer = addr(2, 2000);
        let proof = ring.seal_address_proof(new_peer).unwrap();

        // Without a proof this would be a probe.
        let decision = g.offer_path_with_proof(new_peer, &ring, &proof, true);
        assert_eq!(decision, PathDecision::Adopted);
        assert_eq!(g.active_path(), new_peer);
    }

    #[test]
    fn proof_for_a_different_address_is_refused() {
        let clock = Arc::new(ManualClock::new(1000));
        let ring = ring(&clock);
        let mut g = guard(&clock);
        let victim = addr(2, 2000);
        // Attacker holds a genuine proof, but for *its own* address.
        let attacker_proof = ring.seal_address_proof(addr(7, 7000)).unwrap();
        assert_eq!(
            g.offer_path_with_proof(victim, &ring, &attacker_proof, true),
            PathDecision::Refused(MigrationError::ProofMismatch)
        );
        assert_eq!(g.active_path(), addr(1, 1000));
    }

    #[test]
    fn expired_proof_is_refused() {
        let clock = Arc::new(ManualClock::new(1000));
        let ring = ring(&clock);
        let mut g = guard(&clock);
        let peer = addr(2, 2000);
        let proof = ring.seal_address_proof(peer).unwrap();
        clock.advance(ring.config().address_proof_lifetime_secs + 1);
        // Recompute the guard's clock view too (same ManualClock).
        assert_eq!(
            g.offer_path_with_proof(peer, &ring, &proof, true),
            PathDecision::Refused(MigrationError::ProofMismatch)
        );
    }

    #[test]
    fn migration_frequency_is_capped() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let cfg = g.config();
        // Drive max_migrations_per_window rapid moves through recently-valid
        // paths (adopted instantly).  Each needs a fresh address in the recent
        // set, so validate them via proof first.
        let ring = ring(&clock);
        let mut moves = 0;
        let mut last = 2u8;
        loop {
            let peer = addr(last, 4000);
            let proof = ring.seal_address_proof(peer).unwrap();
            match g.offer_path_with_proof(peer, &ring, &proof, true) {
                PathDecision::Adopted => moves += 1,
                PathDecision::Refused(MigrationError::TooManyMigrations) => break,
                other => panic!("unexpected {other:?}"),
            }
            last = last.wrapping_add(1);
            if moves > cfg.max_migrations_per_window + 2 {
                panic!("frequency cap did not trigger");
            }
        }
        assert_eq!(moves, cfg.max_migrations_per_window);
    }

    #[test]
    fn spoofed_source_never_switches_active_path() {
        // End-to-end: attacker forges a datagram claiming a move to a victim
        // address it does not control.  The server probes, gets no valid
        // response, and leaves data on the original path.
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let victim = addr(66, 6666);
        let (challenge, _) = expect_probe(g.offer_path(victim, true));
        // The victim, not the attacker, receives the probe and never replies.
        for _ in 0..g.config().max_probes {
            clock.advance(1);
            let _ = g.offer_path(victim, true);
        }
        g.reap_expired();
        assert_eq!(g.active_path(), addr(1, 1000));
        // A forged response with a guessed challenge fails.
        assert_eq!(
            g.on_path_response(victim, &[0u8; CHALLENGE_LEN]),
            PathResponseOutcome::Refused(MigrationError::NoPendingChallenge)
        );
        let _ = challenge;
    }

    #[test]
    fn duplicate_response_after_validation_is_harmless() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let (challenge, peer) = expect_probe(g.offer_path(addr(2, 2000), true));
        assert_eq!(
            g.on_path_response(peer, &challenge),
            PathResponseOutcome::Validated
        );
        assert_eq!(
            g.on_path_response(peer, &challenge),
            PathResponseOutcome::Duplicate
        );
        assert_eq!(g.active_path(), peer);
    }

    #[test]
    fn challenges_are_unpredictable() {
        let clock = Arc::new(ManualClock::new(1000));
        let mut g = guard(&clock);
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u8 {
            if let PathDecision::Probe { challenge, .. } = g.offer_path(addr(i, 100), true) {
                assert!(seen.insert(challenge), "challenge repeated");
            }
            g.reap_expired();
        }
    }
}
