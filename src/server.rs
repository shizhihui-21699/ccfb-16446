//! End-to-end server-side admission flow.
//!
//! This module wires the pieces together the way a real server's packet
//! handler would use them, and exists so the security properties can be tested
//! as a whole rather than module by module:
//!
//! ```text
//! Initial (no token)          ->  budget check, issue Retry (token)
//! Initial (Retry token)       ->  verify token, validate address, admit
//! 0-RTT Initial (proof)       ->  verify address proof, admit without Retry
//! Authenticated pkt, new path ->  migration guard: probe / adopt / refuse
//! Path response               ->  verify challenge, switch active path
//! Bytes sent to a peer        ->  settle(), releases the unused reservation
//! ```
//!
//! The `Server` type is deliberately transport-agnostic: it consumes
//! *observations* (a datagram of a given size arrived from an address, carrying
//! such-and-such token) and produces *decisions*.  Accounting is explicit:
//! every authorised send is settled through [`Server::settle`].  The
//! server *reserves* allowance before authorising a send, so a caller that
//! drops the returned action on the floor leaves the reservation in place —
//! which under-sends to a peer rather than over-sending.  That is the safe
//! failure direction for a reflection defence.

use std::collections::HashMap;

use crate::address::PeerAddress;
use crate::amplification::{AddressAmplificationGuard, AntiAmplificationConfig};
use crate::clock::{SharedClock, SystemClock};
use crate::error::TokenError;
use crate::migration::{MigrationConfig, MigrationGuard, PathDecision, PathResponseOutcome};
use crate::ratelimit::RateLimiter;
use crate::token::{TokenConfig, TokenKeyRing, TokenKind};

/// Everything the server needs to decide the fate of one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramObservation {
    /// Source address observed on the wire (untrusted until validated).
    pub from: PeerAddress,
    /// Size of the datagram in bytes.
    pub len: u64,
}

/// What the server directs the caller to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    /// Drop the datagram silently.  No state was created.
    Drop,
    /// Send a Retry carrying `token` toward `peer`.
    SendRetry {
        /// Destination address.
        peer: PeerAddress,
        /// Token to embed in the Retry.
        token: Vec<u8>,
        /// Maximum bytes this Retry may occupy.
        budget_bytes: u64,
    },
    /// Admit traffic toward `peer`.  The caller may send at most
    /// `budget_bytes` and must settle the true amount via [`Server::settle`].
    Admit {
        /// Destination address.
        peer: PeerAddress,
        /// Bytes the caller may send now.
        budget_bytes: u64,
    },
    /// Send a path challenge to `peer`.
    SendPathChallenge {
        /// Address being probed.
        peer: PeerAddress,
        /// Challenge nonce.
        challenge: [u8; crate::migration::CHALLENGE_LEN],
        /// Maximum bytes the probe may occupy.
        budget_bytes: u64,
    },
    /// A path response validated the claimed address; it is now active.
    PathValidated {
        /// The newly active address.
        peer: PeerAddress,
    },
}

/// Policy bundle for [`Server`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    /// Token lifetimes and skew.
    pub token: TokenConfig,
    /// Anti-amplification policy.
    pub amplification: AntiAmplificationConfig,
    /// Migration policy.
    pub migration: MigrationConfig,
    /// Size of a Retry datagram, used to check the budget before issuing one.
    pub retry_wire_bytes: u64,
    /// Size of a path-challenge probe datagram.
    pub probe_wire_bytes: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            token: TokenConfig::default(),
            amplification: AntiAmplificationConfig::default(),
            migration: MigrationConfig::default(),
            retry_wire_bytes: 200,
            probe_wire_bytes: 64,
        }
    }
}

/// A server instance: stateless admission plus per-connection migration state.
///
/// Only connections that had at least one address validated appear here,
/// because [`Server::open_connection`] is called by the caller after
/// admission.  Spoofed handshakes never create a record.
pub struct Server {
    config: ServerConfig,
    ring: TokenKeyRing,
    guard: AddressAmplificationGuard,
    /// Keyed by the stable connection id assigned at validation time.
    connections: HashMap<u64, MigrationGuard>,
    /// Per-peer-IP probe limiter.  Keyed by IP, not port, so an attacker
    /// rotating source ports cannot multiply its probe budget.
    probe_limiter: RateLimiter<std::net::IpAddr>,
    clock: SharedClock,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("connections", &self.connections.len())
            .field("addresses", &self.guard.len())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Build a server sharing the cluster token key ring.
    ///
    /// # Panics
    /// Panics on an invalid configuration; see [`Self::try_new`].
    pub fn new(config: ServerConfig, ring: TokenKeyRing) -> Self {
        Self::try_new(config, ring).expect("valid server configuration")
    }

    /// Fallible constructor.
    pub fn try_new(config: ServerConfig, ring: TokenKeyRing) -> Result<Self, &'static str> {
        Self::try_new_with_clock(config, ring, std::sync::Arc::new(SystemClock))
    }

    /// As [`Self::try_new`] with an explicit shared clock (tests, cluster
    /// clock).
    pub fn try_new_with_clock(
        config: ServerConfig,
        ring: TokenKeyRing,
        clock: SharedClock,
    ) -> Result<Self, &'static str> {
        let guard = AddressAmplificationGuard::try_new(config.amplification, clock.clone())?;
        let probe_limiter = RateLimiter::new(
            config.migration.peer_probe_burst,
            config.migration.peer_probe_refill_per_sec,
            100_000,
            clock.clone(),
        );
        Ok(Self {
            config,
            ring,
            guard,
            connections: HashMap::new(),
            probe_limiter,
            clock,
        })
    }

    /// Convenience for [`Self::try_new`] with an explicit clock.
    pub fn new_with_clock(config: ServerConfig, ring: TokenKeyRing, clock: SharedClock) -> Self {
        Self::try_new_with_clock(config, ring, clock).expect("valid server configuration")
    }

    /// Handle one Initial packet from an address with no connection.
    ///
    /// * A valid Retry token for this address and ODCID validates the address.
    /// * A valid address proof (0-RTT admission) validates it too.
    /// * Otherwise the server issues a Retry, if the budget permits.
    ///
    /// Retry issuance reserves `retry_wire_bytes`; the caller must report the
    /// Retry's true size with [`Self::settle`].
    pub fn handle_initial(
        &mut self,
        from: PeerAddress,
        len: u64,
        odcid: &[u8],
        token: Option<&[u8]>,
    ) -> ServerAction {
        self.guard.on_receive(from, len);

        if let Some(token) = token {
            // Decrypt once, then check the kind.  Token kinds are bound by the
            // AEAD, so a successful decrypt is authoritative.
            if let Ok(verified) = self.ring.decrypt(token) {
                let acceptable = match verified.kind {
                    TokenKind::Retry => {
                        verified.peer == from && verified.odcid.as_deref() == Some(odcid)
                    }
                    TokenKind::AddressProof => verified.peer == from,
                };
                if acceptable {
                    // A token proves the address was reachable when it was
                    // issued; it earns the token tier, not the full one.
                    self.guard.grant_for_token(from);
                    let budget = self.guard.available(from);
                    if self.guard.reserve(from, budget).is_ok() {
                        return ServerAction::Admit {
                            peer: from,
                            budget_bytes: budget,
                        };
                    }
                    return ServerAction::Drop;
                }
            }
            // A rejected token falls through to a fresh Retry so a client
            // holding a stale proof recovers in one round trip instead of
            // being dropped into a black hole.
        }

        let need = self.config.retry_wire_bytes;
        if self.guard.reserve(from, need).is_err() {
            return ServerAction::Drop;
        }
        match self.ring.seal_retry(from, odcid) {
            Ok(token) => ServerAction::SendRetry {
                peer: from,
                token,
                budget_bytes: need,
            },
            Err(_) => {
                // Nothing sent: release the reservation.
                self.guard.settle(from, need, 0);
                ServerAction::Drop
            }
        }
    }

    /// Settle a reservation made by an authorised [`ServerAction`].
    ///
    /// Every action that authorises outbound bytes (`SendRetry`, `Admit`,
    /// `SendPathChallenge`) carries a `budget_bytes` that the server has
    /// already reserved against the peer's ledger.  After transmitting, the
    /// caller reports the number of bytes it actually put on the wire.  The
    /// unused part of the reservation is released; any excess is charged.
    ///
    /// A caller that never settles simply leaves its reservation spent, which
    /// under-grants future traffic to that peer — the safe direction for a
    /// reflection defence.  Returns `false` only when `actual` exceeds both the
    /// reservation and the remaining allowance (a caller bug).
    pub fn settle(&mut self, peer: PeerAddress, reserved: u64, actual: u64) -> bool {
        self.guard.settle(peer, reserved, actual)
    }

    /// Register a validated connection, creating its migration guard.
    pub fn open_connection(&mut self, id: u64, active: PeerAddress) {
        let guard = MigrationGuard::new(active, self.config.migration, self.clock.clone());
        self.connections.insert(id, guard);
    }

    /// Handle an authenticated datagram on connection `id` whose source
    /// address may differ from the connection's active path.
    ///
    /// The caller MUST only call this for datagrams authenticated under the
    /// connection's keys.
    pub fn handle_authenticated(&mut self, id: u64, obs: DatagramObservation) -> ServerAction {
        // Every authenticated datagram credits the source address it came
        // from; that is the only way an unvalidated claim earns budget.
        self.guard.on_receive(obs.from, obs.len);

        let Some(conn) = self.connections.get(&id) else {
            return ServerAction::Drop;
        };
        if conn.active_path() == obs.from {
            let budget = self.guard.available(obs.from);
            // Pre-reserve so a forgotten report cannot amplify; the caller
            // settles to the true size via `settle`.
            if self.guard.reserve(obs.from, budget).is_ok() {
                return ServerAction::Admit {
                    peer: obs.from,
                    budget_bytes: budget,
                };
            }
            return ServerAction::Drop;
        }

        let probe_ok = self.probe_limiter.try_take(&obs.from.ip());
        let decision = self
            .connections
            .get_mut(&id)
            .expect("checked above")
            .offer_path(obs.from, probe_ok);
        self.act_on_path_decision(id, decision)
    }

    /// Offer a path backed by an address-proof token, used when a client's very
    /// first packet after a move carries a cached proof.
    pub fn handle_migration_with_proof(
        &mut self,
        id: u64,
        from: PeerAddress,
        proof: &[u8],
        len: u64,
    ) -> ServerAction {
        self.guard.on_receive(from, len);
        let probe_ok = self.probe_limiter.try_take(&from.ip());
        let ring = &self.ring;
        let Some(conn) = self.connections.get_mut(&id) else {
            return ServerAction::Drop;
        };
        let decision = conn.offer_path_with_proof(from, ring, proof, probe_ok);
        self.act_on_path_decision(id, decision)
    }

    fn act_on_path_decision(&mut self, id: u64, decision: PathDecision) -> ServerAction {
        match decision {
            PathDecision::Current => ServerAction::Drop,
            PathDecision::Adopted => {
                let peer = self.connections[&id].active_path();
                let budget = self.guard.available(peer);
                if self.guard.reserve(peer, budget).is_ok() {
                    return ServerAction::Admit {
                        peer,
                        budget_bytes: budget,
                    };
                }
                ServerAction::Drop
            }
            PathDecision::Probe { peer, challenge } => {
                let need = self.config.probe_wire_bytes;
                if self.guard.reserve(peer, need).is_err() {
                    // Cannot afford the probe: abandon the pending path so its
                    // slot is not wasted on something we cannot verify.
                    if let Some(conn) = self.connections.get_mut(&id) {
                        conn.abandon(peer);
                    }
                    return ServerAction::Drop;
                }
                ServerAction::SendPathChallenge {
                    peer,
                    challenge,
                    budget_bytes: need,
                }
            }
            PathDecision::Refused(_) => ServerAction::Drop,
        }
    }

    /// Handle a datagram carrying a path-challenge echo from `from`.
    pub fn handle_path_response(
        &mut self,
        id: u64,
        from: PeerAddress,
        echoed: &[u8],
    ) -> ServerAction {
        self.guard.on_receive(from, echoed.len() as u64);
        let Some(conn) = self.connections.get_mut(&id) else {
            return ServerAction::Drop;
        };
        match conn.on_path_response(from, echoed) {
            PathResponseOutcome::Validated => {
                // A path-challenge echo is a live round trip: the strongest
                // proof this server can obtain, so unlock the full allowance.
                self.guard.confirm(from);
                ServerAction::PathValidated { peer: from }
            }
            PathResponseOutcome::Duplicate | PathResponseOutcome::Refused(_) => ServerAction::Drop,
        }
    }

    /// Run periodic housekeeping: reap timed-out path validations and sweep
    /// idle amplification entries.
    pub fn tick(&mut self) {
        for conn in self.connections.values_mut() {
            conn.reap_expired();
        }
        self.guard.sweep(300);
    }

    /// Issue an address-proof token for a client that just validated, to be
    /// cached and reused on future connections and after migration.
    pub fn issue_address_proof(&self, peer: PeerAddress) -> Result<Vec<u8>, TokenError> {
        self.ring.seal_address_proof(peer)
    }

    /// The token key ring (read-only).
    pub fn token_ring(&self) -> &TokenKeyRing {
        &self.ring
    }

    /// Number of tracked connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// The active path of connection `id`, if it exists.
    pub fn active_path(&self, id: u64) -> Option<PeerAddress> {
        self.connections.get(&id).map(|c| c.active_path())
    }

    /// Bytes this server believes it may still send toward `peer`.
    pub fn available(&self, peer: PeerAddress) -> u64 {
        self.guard.available(peer)
    }
}
