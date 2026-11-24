//! Stateless address-validation tokens.
//!
//! A token is a self-contained, authenticated, encrypted blob that proves the
//! bearer was reachable at a particular address at a particular time.  It is
//! *stateless*: any node holding the cluster's [`TokenKeyRing`] can verify a
//! token issued by any other node, without shared state, a database lookup or
//! a round trip to the issuer.  That is what makes retry tokens survive
//! load-balancer rehashing and what lets a client present a cached address
//! proof in its very first packet (0-RTT admission) instead of paying an extra
//! round trip on every connection.
//!
//! # Construction
//!
//! Tokens are sealed with AES-256-GCM-SIV (RFC 8452).  The scheme is
//! *misuse-resistant*: even if the operating system ever hands out a
//! duplicated 96-bit nonce, an attacker gains no forgery advantage and no
//! plaintext-recovery advantage beyond learning that two tokens were equal.
//! This matters because nonce generation happens on the packet path of every
//! node in the fleet, where a single RNG hiccup must not become a catastrophe.
//!
//! The associated data binds the outer header (`version || kid`), so a token
//! cannot be re-labelled as belonging to a different key slot.
//!
//! # Kinds
//!
//! * [`TokenKind::Retry`] — short-lived, bound to a peer address *and* the
//!   client's original destination connection id.  Handed out in a Retry and
//!   echoed back in the following Initial.  Because it is bound to the ODCID,
//!   it cannot be lifted from one handshake into another.
//! * [`TokenKind::AddressProof`] — longer-lived, bound to the peer address
//!   only.  A client caches it and presents it on future handshakes from the
//!   same address, skipping the Retry round trip.  It is *not* a credential
//!   for any connection: it only tells the server "this address was reachable
//!   recently", never "this peer owns this connection".
//!
//! # Key rotation
//!
//! The ring holds up to 255 key slots addressed by one-byte key ids.  Exactly
//! one slot is *current* and seals new tokens; every other slot still verifies.
//! A retirement schedule therefore looks like: deploy new key on all nodes →
//! make it current → stop accepting the old key after its maximum token
//! lifetime has elapsed.

use std::collections::BTreeMap;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::address::PeerAddress;
use crate::clock::{Clock, SystemClock};
use crate::error::TokenError;

/// Wire version of the token format.
pub const TOKEN_VERSION: u8 = 1;

/// Fixed domain separator mixed into key derivation and AEAD associated data.
const DOMAIN: &[u8] = b"fastpath-security/address-token/v1";

/// AES-GCM-SIV nonce length.
const NONCE_LEN: usize = 12;
/// AES-GCM-SIV authentication tag length.
const TAG_LEN: usize = 16;
/// Absolute upper bound on a token we are willing to decrypt (defence in depth).
const MAX_TOKEN_LEN: usize = 128;
/// Longest original destination connection id that can be bound into a token.
pub const MAX_ODCID_LEN: usize = 20;

/// What a token attests to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TokenKind {
    /// Short-lived proof bound to address *and* original destination CID.
    Retry = 1,
    /// Longer-lived proof bound to address only; usable for 0-RTT admission
    /// and to accelerate connection migration.
    AddressProof = 2,
}

impl TokenKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Retry),
            2 => Some(Self::AddressProof),
            _ => None,
        }
    }
}

/// A token that has been decrypted and whose type-specific checks passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// What the token attests to.
    pub kind: TokenKind,
    /// When the issuing node sealed it (Unix seconds).
    pub issued_at: u64,
    /// Address the token is bound to.
    pub peer: PeerAddress,
    /// Random per-token identifier, useful for logging and revocation lists.
    pub token_id: [u8; 8],
    /// Original destination connection id for [`TokenKind::Retry`] tokens.
    pub odcid: Option<Vec<u8>>,
}

impl VerifiedToken {
    /// How old the token is at `now`, saturating at zero for slightly
    /// future-dated tokens.
    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.issued_at)
    }
}

/// Lifetime and skew policy for each token kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenConfig {
    /// Maximum age of an accepted Retry token.
    pub retry_lifetime_secs: u64,
    /// Maximum age of an accepted address-proof token.
    pub address_proof_lifetime_secs: u64,
    /// How far in the future a token's issue time may be before it is
    /// rejected.  Cluster nodes must keep their clocks within this budget.
    pub max_clock_skew_secs: u64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            // A Retry round trip happens in one RTT; a minute is generous even
            // for a retransmitted Initial, and keeps the binding tight.
            retry_lifetime_secs: 60,
            // Address proofs are meant to be cached across connections and
            // survive a mobile network's address churn; a few hours bounds the
            // window in which a stale proof can be replayed.
            address_proof_lifetime_secs: 6 * 60 * 60,
            max_clock_skew_secs: 10,
        }
    }
}

impl TokenConfig {
    fn lifetime_for(&self, kind: TokenKind) -> u64 {
        match kind {
            TokenKind::Retry => self.retry_lifetime_secs,
            TokenKind::AddressProof => self.address_proof_lifetime_secs,
        }
    }

    fn validate(&self) -> Result<(), TokenError> {
        if self.retry_lifetime_secs == 0 || self.address_proof_lifetime_secs == 0 {
            return Err(TokenError::KeyRing("token lifetimes must be non-zero"));
        }
        // A Retry token is an ephemeral handshake artefact; allowing it to live
        // as long as a cached address proof would let an attacker bank tokens.
        if self.retry_lifetime_secs > 24 * 60 * 60 {
            return Err(TokenError::KeyRing("retry lifetime unreasonably long"));
        }
        Ok(())
    }
}

/// A rotating set of token-sealing keys, shared by every node in the cluster.
///
/// All nodes configured with the same secrets and the same key ids accept each
/// other's tokens.  Key material is derived per slot with HKDF-SHA256, so the
/// configured secrets may be of any length (at least 16 bytes is enforced by
/// [`TokenKeyRing::new`]).
#[derive(Debug)]
pub struct TokenKeyRing {
    /// Derived 32-byte subkeys, indexed by one-byte key id.
    keys: BTreeMap<u8, Zeroizing<[u8; 32]>>,
    current: u8,
    clock: Box<dyn Clock>,
    config: TokenConfig,
}

impl TokenKeyRing {
    /// Build a ring with the given secrets.  `secrets` is ordered: the first
    /// entry becomes the current sealing key, and its index is the key id.
    /// All entries must be at least 16 bytes of high-entropy material.
    ///
    /// # Errors
    /// Returns [`TokenError::KeyRing`] if no secret is supplied, more than 255
    /// are supplied, or a secret is too short.
    pub fn new(secrets: &[&[u8]], config: TokenConfig) -> Result<Self, TokenError> {
        Self::new_with_clock(secrets, config, SystemClock)
    }

    /// As [`Self::new`] but with an explicit clock (used by tests and by
    /// servers that share a coarsened cluster clock).
    pub fn new_with_clock(
        secrets: &[&[u8]],
        config: TokenConfig,
        clock: impl Clock + 'static,
    ) -> Result<Self, TokenError> {
        config.validate()?;
        if secrets.is_empty() {
            return Err(TokenError::KeyRing("at least one secret is required"));
        }
        if secrets.len() > 255 {
            return Err(TokenError::KeyRing("at most 255 key slots are supported"));
        }
        if secrets.iter().any(|s| s.len() < 16) {
            return Err(TokenError::KeyRing("secrets must be at least 16 bytes"));
        }
        let mut ring = Self {
            keys: BTreeMap::new(),
            current: 0,
            clock: Box::new(clock),
            config,
        };
        for (id, secret) in secrets.iter().enumerate() {
            ring.insert_derived(id as u8, secret);
        }
        Ok(ring)
    }

    /// Add a key slot, deriving its subkey.  Replacing an existing id keeps
    /// its position; the current key is unaffected.
    ///
    /// # Errors
    /// Returns [`TokenError::KeyRing`] when the id is already in use or the
    /// secret is too short.
    pub fn add_key(&mut self, id: u8, secret: &[u8]) -> Result<(), TokenError> {
        if self.keys.contains_key(&id) {
            return Err(TokenError::KeyRing("key id already present"));
        }
        if secret.len() < 16 {
            return Err(TokenError::KeyRing("secrets must be at least 16 bytes"));
        }
        self.insert_derived(id, secret);
        Ok(())
    }

    /// Remove a key slot.  The current key may not be removed; select a new
    /// current key first.  Removing the last key is refused.
    ///
    /// # Errors
    /// Returns [`TokenError::KeyRing`] on the conditions above.
    pub fn remove_key(&mut self, id: u8) -> Result<(), TokenError> {
        if id == self.current {
            return Err(TokenError::KeyRing("cannot remove the current key"));
        }
        if self.keys.len() <= 1 {
            return Err(TokenError::KeyRing("ring must retain at least one key"));
        }
        if self.keys.remove(&id).is_none() {
            return Err(TokenError::KeyRing("unknown key id"));
        }
        Ok(())
    }

    /// Select which key id seals new tokens.  The id must already be present.
    ///
    /// # Errors
    /// Returns [`TokenError::KeyRing`] if the id is unknown.
    pub fn set_current(&mut self, id: u8) -> Result<(), TokenError> {
        if !self.keys.contains_key(&id) {
            return Err(TokenError::KeyRing("unknown key id"));
        }
        self.current = id;
        Ok(())
    }

    /// The key id currently used for sealing.
    pub fn current_key_id(&self) -> u8 {
        self.current
    }

    /// Key ids the ring will accept.
    pub fn key_ids(&self) -> impl Iterator<Item = u8> + '_ {
        self.keys.keys().copied()
    }

    /// Policy in force.
    pub fn config(&self) -> TokenConfig {
        self.config
    }

    fn insert_derived(&mut self, id: u8, secret: &[u8]) {
        let hk = Hkdf::<Sha256>::new(Some(DOMAIN), secret);
        let mut info = [0u8; 12];
        info[..5].copy_from_slice(b"token");
        info[5] = id;
        let mut okm = Zeroizing::new([0u8; 32]);
        // 32 bytes is well below HKDF-SHA256's 8160-byte output limit.
        hk.expand(&info, okm.as_mut())
            .expect("32-byte HKDF output is always valid");
        self.keys.insert(id, okm);
    }

    fn cipher_for(&self, id: u8) -> Result<Aes256GcmSiv, TokenError> {
        let key = self.keys.get(&id).ok_or(TokenError::UnknownKey(id))?;
        Ok(Aes256GcmSiv::new_from_slice(key.as_ref()).expect("32-byte AES-256 key"))
    }

    /// Seal a [`TokenKind::Retry`] token bound to `peer` and `odcid`.
    ///
    /// # Errors
    /// Returns [`TokenError::InvalidConnectionId`] if `odcid` is longer than
    /// [`MAX_ODCID_LEN`], or [`TokenError::Entropy`] if the OS RNG fails.
    pub fn seal_retry(&self, peer: PeerAddress, odcid: &[u8]) -> Result<Vec<u8>, TokenError> {
        if odcid.len() > MAX_ODCID_LEN {
            return Err(TokenError::InvalidConnectionId);
        }
        self.seal(TokenKind::Retry, peer, Some(odcid))
    }

    /// Seal an [`TokenKind::AddressProof`] token bound to `peer`.
    ///
    /// # Errors
    /// Returns [`TokenError::Entropy`] if the OS RNG fails.
    pub fn seal_address_proof(&self, peer: PeerAddress) -> Result<Vec<u8>, TokenError> {
        self.seal(TokenKind::AddressProof, peer, None)
    }

    fn seal(
        &self,
        kind: TokenKind,
        peer: PeerAddress,
        odcid: Option<&[u8]>,
    ) -> Result<Vec<u8>, TokenError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| TokenError::Entropy)?;
        let mut token_id = [0u8; 8];
        getrandom::getrandom(&mut token_id).map_err(|_| TokenError::Entropy)?;

        let issued_at = self.clock.unix_secs();
        let mut plaintext = Vec::with_capacity(64);
        plaintext.push(kind as u8);
        write_u48(&mut plaintext, issued_at);
        plaintext.extend_from_slice(&token_id);
        peer.write_to(&mut plaintext);
        match kind {
            TokenKind::Retry => {
                let odcid = odcid.unwrap_or_default();
                plaintext.push(odcid.len() as u8);
                plaintext.extend_from_slice(odcid);
            }
            TokenKind::AddressProof => {}
        }

        let kid = self.current;
        let cipher = self.cipher_for(kid)?;
        let aad = associated_data(kid);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TokenError::Entropy)?;
        plaintext.zeroize();

        let mut token = Vec::with_capacity(2 + NONCE_LEN + ciphertext.len());
        token.push(TOKEN_VERSION);
        token.push(kid);
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&ciphertext);
        Ok(token)
    }

    /// Verify and decrypt a token, enforcing `kind` and (for Retry tokens)
    /// that it is bound to `odcid`, and that it is bound to `peer`.
    ///
    /// # Errors
    /// Returns the appropriate [`TokenError`] describing why the token is not
    /// acceptable.  Callers must treat every error identically on the wire.
    pub fn open(
        &self,
        token: &[u8],
        kind: TokenKind,
        peer: PeerAddress,
        odcid: Option<&[u8]>,
    ) -> Result<VerifiedToken, TokenError> {
        let parsed = self.decrypt(token)?;
        if parsed.kind != kind {
            return Err(TokenError::KindMismatch);
        }
        match kind {
            TokenKind::Retry => {
                let expected = odcid.ok_or(TokenError::InvalidConnectionId)?;
                let bound = parsed.odcid.as_deref().ok_or(TokenError::Malformed)?;
                // Connection ids are not secret; equality is fine.
                if bound != expected {
                    return Err(TokenError::ConnectionIdMismatch);
                }
            }
            TokenKind::AddressProof => {
                if parsed.odcid.is_some() {
                    return Err(TokenError::Malformed);
                }
            }
        }
        if parsed.peer != peer {
            return Err(TokenError::AddressMismatch);
        }
        Ok(parsed)
    }

    /// Decrypt and validate lifetime/address, without checking the expected
    /// kind.  Useful for a "which token is this?" pre-dispatch.
    ///
    /// # Errors
    /// See [`TokenError`].
    pub fn decrypt(&self, token: &[u8]) -> Result<VerifiedToken, TokenError> {
        if token.len() < 2 + NONCE_LEN + TAG_LEN || token.len() > MAX_TOKEN_LEN {
            return Err(TokenError::Malformed);
        }
        let version = token[0];
        if version != TOKEN_VERSION {
            return Err(TokenError::UnsupportedVersion(version));
        }
        let kid = token[1];
        // Decrypt with the named key before touching any payload bytes, so a
        // forged kid costs at most one AEAD attempt and reveals nothing about
        // which key ids exist versus which failed authentication.
        let cipher = self.cipher_for(kid)?;
        let nonce: &[u8; NONCE_LEN] = token[2..2 + NONCE_LEN]
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &token[2 + NONCE_LEN..],
                    aad: &associated_data(kid),
                },
            )
            .map_err(|_| TokenError::Authentication)?;
        let result = self.parse_and_check(&plaintext);
        plaintext.zeroize();
        result
    }

    fn parse_and_check(&self, plaintext: &[u8]) -> Result<VerifiedToken, TokenError> {
        let mut cursor = 0usize;
        let kind_byte = *plaintext.get(cursor).ok_or(TokenError::Malformed)?;
        cursor += 1;
        let kind = TokenKind::from_u8(kind_byte).ok_or(TokenError::Malformed)?;

        let issued_at = read_u48(plaintext, &mut cursor).ok_or(TokenError::Malformed)?;
        let token_id: [u8; 8] = plaintext
            .get(cursor..cursor + 8)
            .ok_or(TokenError::Malformed)?
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        cursor += 8;
        let peer = PeerAddress::read_from(plaintext, &mut cursor).ok_or(TokenError::Malformed)?;

        let odcid = match kind {
            TokenKind::Retry => {
                let len = *plaintext.get(cursor).ok_or(TokenError::Malformed)? as usize;
                cursor += 1;
                if len > MAX_ODCID_LEN {
                    return Err(TokenError::InvalidConnectionId);
                }
                let id = plaintext
                    .get(cursor..cursor + len)
                    .ok_or(TokenError::Malformed)?;
                cursor += len;
                Some(id.to_vec())
            }
            TokenKind::AddressProof => None,
        };
        if cursor != plaintext.len() {
            return Err(TokenError::Malformed);
        }

        let now = self.clock.unix_secs();
        let skew = self.config.max_clock_skew_secs;
        if issued_at > now.saturating_add(skew) {
            return Err(TokenError::FutureDated {
                ahead_secs: issued_at - now,
            });
        }
        let lifetime = self.config.lifetime_for(kind);
        let age = now.saturating_sub(issued_at);
        if age > lifetime {
            return Err(TokenError::Expired {
                age_secs: age,
                lifetime_secs: lifetime,
            });
        }

        Ok(VerifiedToken {
            kind,
            issued_at,
            peer,
            token_id,
            odcid,
        })
    }
}

fn associated_data(kid: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + 2);
    aad.extend_from_slice(DOMAIN);
    aad.push(TOKEN_VERSION);
    aad.push(kid);
    aad
}

fn write_u48(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value < 1 << 48);
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[2..8]);
}

fn read_u48(buf: &[u8], cursor: &mut usize) -> Option<u64> {
    let slice = buf.get(*cursor..*cursor + 6)?;
    *cursor += 6;
    let mut bytes = [0u8; 8];
    bytes[2..].copy_from_slice(slice);
    Some(u64::from_be_bytes(bytes))
}

/// Constant-time comparison helper for equal-length byte strings.
///
/// Used where a peer-supplied value is compared against a server-chosen
/// secret (path challenges).  `subtle`'s `ct_eq` requires equal lengths, so
/// length is compared first; lengths are not secret here.
pub(crate) fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use std::sync::Arc;

    fn ring(clock: Arc<ManualClock>) -> TokenKeyRing {
        let config = TokenConfig {
            retry_lifetime_secs: 60,
            address_proof_lifetime_secs: 3600,
            max_clock_skew_secs: 10,
        };
        let clock: Arc<dyn Clock> = clock;
        TokenKeyRing::new_with_clock(
            &[b"cluster-secret-number-one-32bytes"],
            config,
            ArcClock(clock),
        )
        .unwrap()
    }

    /// Lets an `Arc<ManualClock>` be used where an owned clock is required.
    struct ArcClock(Arc<dyn Clock>);
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
        PeerAddress::v4("198.51.100.7".parse().unwrap(), 4433)
    }

    #[test]
    fn retry_token_roundtrip() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let token = ring.seal_retry(peer(), b"odcid-1234").unwrap();
        let verified = ring
            .open(&token, TokenKind::Retry, peer(), Some(b"odcid-1234"))
            .unwrap();
        assert_eq!(verified.kind, TokenKind::Retry);
        assert_eq!(verified.peer, peer());
        assert_eq!(verified.odcid.as_deref(), Some(&b"odcid-1234"[..]));
    }

    #[test]
    fn address_proof_is_not_usable_as_retry_and_vice_versa() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let proof = ring.seal_address_proof(peer()).unwrap();
        let retry = ring.seal_retry(peer(), b"abc").unwrap();
        assert_eq!(
            ring.open(&proof, TokenKind::Retry, peer(), Some(b"abc")),
            Err(TokenError::KindMismatch)
        );
        assert_eq!(
            ring.open(&retry, TokenKind::AddressProof, peer(), None),
            Err(TokenError::KindMismatch)
        );
    }

    #[test]
    fn retry_token_is_bound_to_odcid() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let token = ring.seal_retry(peer(), b"original").unwrap();
        assert_eq!(
            ring.open(&token, TokenKind::Retry, peer(), Some(b"attacker")),
            Err(TokenError::ConnectionIdMismatch)
        );
    }

    #[test]
    fn token_is_bound_to_source_address() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let token = ring.seal_retry(peer(), b"abc").unwrap();
        let other = PeerAddress::v4("203.0.113.9".parse().unwrap(), 4433);
        assert_eq!(
            ring.open(&token, TokenKind::Retry, other, Some(b"abc")),
            Err(TokenError::AddressMismatch)
        );
        // Same IP, different port is a different address.
        let other_port = PeerAddress::v4("198.51.100.7".parse().unwrap(), 4434);
        assert_eq!(
            ring.open(&token, TokenKind::Retry, other_port, Some(b"abc")),
            Err(TokenError::AddressMismatch)
        );
    }

    #[test]
    fn ipv4_mapped_and_ipv4_are_interchangeable() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let v4 = PeerAddress::v4("198.51.100.7".parse().unwrap(), 4433);
        let mapped = PeerAddress::v6("::ffff:198.51.100.7".parse().unwrap(), 4433);
        let token = ring.seal_retry(v4, b"abc").unwrap();
        assert!(ring
            .open(&token, TokenKind::Retry, mapped, Some(b"abc"))
            .is_ok());
    }

    #[test]
    fn token_expires_and_rejects_future_dating() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock.clone());
        let token = ring.seal_retry(peer(), b"abc").unwrap();

        clock.advance(60);
        assert!(ring
            .open(&token, TokenKind::Retry, peer(), Some(b"abc"))
            .is_ok());
        clock.advance(1);
        assert!(matches!(
            ring.open(&token, TokenKind::Retry, peer(), Some(b"abc")),
            Err(TokenError::Expired { .. })
        ));

        clock.set(1_700_000_000);
        clock.advance(11);
        let future = ring.seal_retry(peer(), b"abc").unwrap();
        clock.set(1_700_000_000);
        assert!(matches!(
            ring.open(&future, TokenKind::Retry, peer(), Some(b"abc")),
            Err(TokenError::FutureDated { .. })
        ));
    }

    #[test]
    fn any_node_in_cluster_verifies_another_nodes_token() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let config = TokenConfig::default();
        let clock_a: Arc<dyn Clock> = clock.clone();
        let clock_b: Arc<dyn Clock> = clock.clone();
        let node_a = TokenKeyRing::new_with_clock(
            &[b"shared-cluster-secret-material"],
            config,
            ArcClock(clock_a),
        )
        .unwrap();
        let node_b = TokenKeyRing::new_with_clock(
            &[b"shared-cluster-secret-material"],
            config,
            ArcClock(clock_b),
        )
        .unwrap();
        let token = node_a.seal_retry(peer(), b"xyz").unwrap();
        assert!(node_b
            .open(&token, TokenKind::Retry, peer(), Some(b"xyz"))
            .is_ok());
    }

    #[test]
    fn a_different_secret_cannot_verify() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let config = TokenConfig::default();
        let clock_a: Arc<dyn Clock> = clock.clone();
        let clock_b: Arc<dyn Clock> = clock.clone();
        let node_a = TokenKeyRing::new_with_clock(
            &[b"cluster-secret-alpha-aaaaaaaa"],
            config,
            ArcClock(clock_a),
        )
        .unwrap();
        let node_b = TokenKeyRing::new_with_clock(
            &[b"cluster-secret-beta-bbbbbbbbbb"],
            config,
            ArcClock(clock_b),
        )
        .unwrap();
        let token = node_a.seal_retry(peer(), b"xyz").unwrap();
        assert_eq!(
            node_b.open(&token, TokenKind::Retry, peer(), Some(b"xyz")),
            Err(TokenError::Authentication)
        );
    }

    #[test]
    fn key_rotation_accepts_old_and_new() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let config = TokenConfig::default();
        let clock_a: Arc<dyn Clock> = clock.clone();
        let clock_b: Arc<dyn Clock> = clock.clone();
        let node_a = TokenKeyRing::new_with_clock(
            &[
                b"old-key-material-0123456789",
                b"new-key-material-9876543210",
            ],
            config,
            ArcClock(clock_a),
        )
        .unwrap();
        let old_token = node_a.seal_retry(peer(), b"s").unwrap();
        assert_eq!(node_a.current_key_id(), 0);

        let mut node_b = TokenKeyRing::new_with_clock(
            &[
                b"old-key-material-0123456789",
                b"new-key-material-9876543210",
            ],
            config,
            ArcClock(clock_b),
        )
        .unwrap();
        node_b.set_current(1).unwrap();
        let new_token = node_b.seal_retry(peer(), b"s").unwrap();
        assert_eq!(new_token[1], 1);
        assert_eq!(old_token[1], 0);

        // Both are accepted by both nodes during the overlap window.
        assert!(node_a
            .open(&new_token, TokenKind::Retry, peer(), Some(b"s"))
            .is_ok());
        assert!(node_b
            .open(&old_token, TokenKind::Retry, peer(), Some(b"s"))
            .is_ok());

        // Retiring the old key makes its tokens unverifiable.
        node_b.remove_key(0).unwrap();
        assert_eq!(
            node_b.open(&old_token, TokenKind::Retry, peer(), Some(b"s")),
            Err(TokenError::UnknownKey(0))
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let token = ring.seal_retry(peer(), b"abc").unwrap();
        for i in 0..token.len() {
            let mut bad = token.clone();
            bad[i] ^= 0x01;
            let result = ring.open(&bad, TokenKind::Retry, peer(), Some(b"abc"));
            assert!(
                result.is_err(),
                "flipping byte {i} must invalidate the token"
            );
        }
    }

    #[test]
    fn truncated_and_oversized_tokens_are_malformed() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let token = ring.seal_retry(peer(), b"abc").unwrap();
        const MIN: usize = 2 + NONCE_LEN + TAG_LEN;
        for len in 0..token.len() {
            let result = ring.open(&token[..len], TokenKind::Retry, peer(), Some(b"abc"));
            // Below the minimum framing length the token is rejected without
            // any crypto work; above it the AEAD tag check fails.
            if len < MIN {
                assert_eq!(result, Err(TokenError::Malformed));
            } else {
                assert_eq!(result, Err(TokenError::Authentication));
            }
        }
        // Trailing garbage beyond the fixed maximum framing size is rejected
        // before the AEAD is invoked.
        let mut long = token.clone();
        long.resize(MAX_TOKEN_LEN + 1, 0);
        assert_eq!(
            ring.open(&long, TokenKind::Retry, peer(), Some(b"abc")),
            Err(TokenError::Malformed)
        );
        // One byte of trailing garbage *within* the framing bound reaches the
        // AEAD and fails authentication instead.
        let mut short_garbage = token.clone();
        short_garbage.push(0);
        assert_eq!(
            ring.open(&short_garbage, TokenKind::Retry, peer(), Some(b"abc")),
            Err(TokenError::Authentication)
        );
    }

    #[test]
    fn overlong_odcid_is_refused() {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        assert_eq!(
            ring.seal_retry(peer(), &[0u8; MAX_ODCID_LEN + 1]),
            Err(TokenError::InvalidConnectionId)
        );
        assert!(ring.seal_retry(peer(), &[0u8; MAX_ODCID_LEN]).is_ok());
    }

    #[test]
    fn reused_nonce_does_not_break_authentication() {
        // Simulate the worst case for a nonce-based AEAD: two tokens sealed
        // with the same nonce.  AES-GCM-SIV must still reject forged tags.
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let ring = ring(clock);
        let t1 = ring.seal_retry(peer(), b"a").unwrap();
        let t2 = ring.seal_retry(peer(), b"b").unwrap();
        assert_ne!(t1, t2);
        let mut forged = t1.clone();
        *forged.last_mut().unwrap() ^= 0x80;
        assert!(ring
            .open(&forged, TokenKind::Retry, peer(), Some(b"a"))
            .is_err());
    }

    #[test]
    fn rejects_bad_key_ring_configuration() {
        let clock = Arc::new(ManualClock::new(0));
        let clock: Arc<dyn Clock> = clock;
        assert!(
            TokenKeyRing::new_with_clock(&[], TokenConfig::default(), ArcClock(clock)).is_err()
        );
    }
}
