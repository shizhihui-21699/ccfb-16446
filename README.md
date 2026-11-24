# fastpath-security

Stateless address validation, anti-amplification and secure connection
migration for a QUIC-like transport running on connectionless datagrams.

The crate addresses two attacks against a datagram server:

1. **Reflection / amplification.** An attacker spoofs a victim's source address
   and sends a small handshake packet. If the server answers with a large
   handshake response, the victim receives traffic it never asked for.
2. **Connection hijack by forged migration.** An attacker forges a packet
   claiming the peer has moved to an address it controls, hoping the server
   rebinds the victim's connection there.

It is designed around three properties that a real deployment needs:

* **Stateless tokens** — any node in the fleet can verify a token any other
  node issued, with no shared database and no round trip. This survives
  load-balancer rehashing and lets clients skip a round trip with a cached
  proof.
* **Path validation** — a new address is never trusted on the strength of one
  packet. It must answer a random challenge, and probes are rate-limited,
  count-capped and amplification-bounded.
* **Mobile-friendly** — legitimate address churn (Wi-Fi ↔ cellular, NAT
  rebinding, roaming) is cheap: recently-proven addresses are re-adopted without
  a probe, and a cached address proof admits a client in its first packet.

## Quick start

```rust
use std::sync::Arc;
use fastpath_security::address::PeerAddress;
use fastpath_security::clock::ManualClock;
use fastpath_security::server::{Server, ServerAction, ServerConfig};
use fastpath_security::token::{TokenConfig, TokenKeyRing};

// Every node in the cluster is configured with the same secrets and key ids.
// The first secret is current and seals new tokens; all of them still verify.
let clock: fastpath_security::clock::SharedClock = Arc::new(ManualClock::new(1_700_000_000));
let ring = TokenKeyRing::new_with_clock(
    &[b"cluster-secret-2025-aaaaaaaaaaaa"],
    TokenConfig::default(),
    clock.clone(),
).unwrap();
let mut server = Server::new_with_clock(ServerConfig::default(), ring, clock);

let client = PeerAddress::v4("198.51.100.20".parse().unwrap(), 4433);
let odcid = b"client-chosen-odcid";

// 1. First Initial: no token, so the server issues a Retry.
let token = match server.handle_initial(client, 1200, odcid, None) {
    ServerAction::SendRetry { token, budget_bytes, .. } => {
        server.settle(client, budget_bytes, 200); // report the Retry actually sent
        token
    }
    other => panic!("expected Retry, got {other:?}"),
};

// 2. Client echoes the token: address validated, handshake proceeds.
match server.handle_initial(client, 1200, odcid, Some(&token)) {
    ServerAction::Admit { budget_bytes, .. } => {
        server.settle(client, budget_bytes, 1200);
    }
    other => panic!("expected admission, got {other:?}"),
}
```

## How it fits together

| Module | Responsibility |
| --- | --- |
| [`token`] | Stateless Retry tokens and cached address proofs (AES-256-GCM-SIV, rotating key ring). |
| [`amplification`] | Per-address byte ledger with three allowance tiers. |
| [`migration`] | Per-connection path validation: challenge, adopt, refuse. |
| [`ratelimit`] | Token-bucket limiter backing the per-IP probe budget. |
| [`server`] | Wires the above into a transport-agnostic admission flow. |
| [`address`] | Canonical peer address used for token binding. |
| [`clock`] | Injectable time source; [`clock::ManualClock`] for deterministic tests. |

## Security model and its boundaries

**What this crate does.** It decides whether a *datagram from an address* may
cause the server to *send bytes back to that address*. It never decides whether
a datagram belongs to a connection — that is the packet-protection layer's job
(HPKE/tls keys, which are out of scope). `Server::handle_authenticated` must
only be called for datagrams whose protection has already been verified.

**Tokens are not credentials.** A token proves "this address was reachable when
this token was issued". It does **not** prove "this peer owns connection X". A
Retry token is additionally bound to the client's original destination
connection id so it cannot be lifted between handshakes; an address proof is
bound to the address only, by design, so it can be cached and reused. Neither
may be used to authorise application data; they authorise a small handshake
burst (the *token tier*).

**Allowance tiers.** Anti-amplification credit is granted in three steps, each
strictly larger than the last and each granted at most once per peer:

| Tier | Granted when | Purpose |
| --- | --- | --- |
| none | — | `min(received × 3, burst_cap)` only |
| token | a valid token or cached proof | finish a handshake (`token_floor`) |
| confirmed | a live path-challenge echo | full data flight (`validated_floor`) |

Because each bootstrap is granted once, re-presenting a token or re-validating
a path cannot reset a peer's spend, so the reflection bound holds even under
token replay.

**Clock assumptions.** Token lifetime and skew are enforced against the node's
clock. Cluster nodes must keep their clocks within
`TokenConfig::max_clock_skew_secs`; a node whose clock runs far ahead will reject
tokens from nodes behind it. Tokens are bit-packed to 48-bit timestamps, good
for ~8900 years.

**Non-goals.** Traffic analysis, connection-id routing, key exchange and packet
protection are out of scope. The crate does not try to hide *whether* a server
is willing to talk to an address, beyond the fact that it will not amplify.

## Testing

`cargo test` runs unit tests per module plus end-to-end tests in
`tests/end_to_end.rs` that assert, among other things:

* a 1-byte spoofed packet does not earn a 200-byte Retry;
* a token issued by one node is accepted by another;
* a token is rejected from a different address, a different ODCID, or after
  expiry;
* a forged migration claim never switches the active path, and probe traffic to
  the forged (victim) address stays within the amplification bound;
* key rotation accepts old and new tokens during the overlap window;
* rapid legitimate Wi-Fi ↔ cellular flapping is adopted without a round trip.
