//! Error types shared across the crate.

use thiserror::Error;

/// Reasons a token can fail verification.
///
/// Variants are deliberately coarse for the caller: they are safe to log, but
/// should not all be surfaced to a peer (an unknown key id and a forged tag
/// must look alike from outside).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The token is shorter or longer than any valid token.
    #[error("malformed token")]
    Malformed,
    /// Unknown outer format version.
    #[error("unsupported token version {0}")]
    UnsupportedVersion(u8),
    /// The token was sealed under a key id that this node does not hold.
    #[error("unknown token key id {0}")]
    UnknownKey(u8),
    /// The AEAD tag did not verify.
    #[error("token authentication failed")]
    Authentication,
    /// The token is older than its kind's lifetime.
    #[error("token expired: age {age_secs}s exceeds lifetime {lifetime_secs}s")]
    Expired {
        /// Seconds between issuance and verification.
        age_secs: u64,
        /// Configured lifetime for this token kind.
        lifetime_secs: u64,
    },
    /// The token's issue time is too far in the future (clock skew or forgery).
    #[error("token issued {ahead_secs}s in the future")]
    FutureDated {
        /// How far ahead of the local clock the token claims to be.
        ahead_secs: u64,
    },
    /// The token is bound to a different source address.
    #[error("token is bound to a different address")]
    AddressMismatch,
    /// A path token was presented where a Retry token was required, or vice versa.
    #[error("token kind mismatch")]
    KindMismatch,
    /// The token is bound to a different original destination connection id.
    #[error("token is bound to a different connection id")]
    ConnectionIdMismatch,
    /// The token is bound to an original destination connection id of an
    /// unsupported length.
    #[error("original destination connection id is invalid")]
    InvalidConnectionId,
    /// The operating system entropy source failed.
    #[error("entropy source unavailable")]
    Entropy,
    /// The key ring is empty, full, or has an inconsistent current key.
    #[error("key ring misconfigured: {0}")]
    KeyRing(&'static str),
}

/// Why an outbound datagram was refused by the anti-amplification guard.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("amplification limit: requested {requested} bytes, {available} available")]
pub struct AmplificationBlocked {
    /// Bytes the caller wanted to send.
    pub requested: u64,
    /// Bytes still allowed to this address right now.
    pub available: u64,
}

/// Why a migration or path-validation step was refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    /// The claimed path could not be probed because the global per-IP probe
    /// budget for this peer is exhausted.
    #[error("path probe rate limit exceeded for peer")]
    ProbeRateLimited,
    /// The connection already has the maximum number of unvalidated paths in
    /// flight.
    #[error("too many pending paths for this connection")]
    TooManyPendingPaths,
    /// The connection changed paths too often in the last minute.
    #[error("connection migrated too frequently")]
    TooManyMigrations,
    /// A path response arrived for an address with no outstanding challenge.
    #[error("no outstanding challenge for this path")]
    NoPendingChallenge,
    /// The path response did not echo the challenge.
    #[error("path response did not match the challenge")]
    ChallengeMismatch,
    /// The proof token does not name this address.
    #[error("address proof does not match the claimed address")]
    ProofMismatch,
    /// The pending path was abandoned after too many unanswered probes.
    #[error("path validation timed out")]
    ValidationTimedOut,
}

/// Configuration rejected at construction time.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A numeric knob was outside its valid range.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}
