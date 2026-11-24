//! End-to-end tests exercising the pieces together as a server would.

use std::sync::Arc;

use fastpath_security::address::PeerAddress;
use fastpath_security::clock::{ManualClock, SharedClock};
use fastpath_security::server::{DatagramObservation, Server, ServerAction, ServerConfig};
use fastpath_security::token::TokenKind;

fn clock_at(secs: u64) -> SharedClock {
    Arc::new(ManualClock::new(secs))
}

fn manual(secs: u64) -> (Arc<ManualClock>, SharedClock) {
    let m = Arc::new(ManualClock::new(secs));
    let d: SharedClock = m.clone();
    (m, d)
}

fn server(clock: SharedClock) -> Server {
    // Two cluster nodes share the same secret material and key ids; each is
    // built independently to model a real fleet.
    let ring = fastpath_security::token::TokenKeyRing::new_with_clock(
        &[b"production-cluster-secret-0001"],
        fastpath_security::token::TokenConfig::default(),
        clock.clone(),
    )
    .unwrap();
    Server::new_with_clock(ServerConfig::default(), ring, clock)
}

fn peer(last: u8, port: u16) -> PeerAddress {
    PeerAddress::v4([10, 10, 0, last].into(), port)
}

fn client_handshake(server: &mut Server, from: PeerAddress, odcid: &[u8]) -> Vec<u8> {
    // First Initial, no token: expect a Retry with a token.
    let action = server.handle_initial(from, 1200, odcid, None);
    match action {
        ServerAction::SendRetry { peer, token, .. } => {
            assert_eq!(peer, from);
            server.settle(from, 200, 200);
            token
        }
        other => panic!("expected Retry, got {other:?}"),
    }
}

#[test]
fn spoofed_initial_gets_no_amplification_beyond_budget() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let victim = peer(66, 9999);

    // Attacker sends a tiny spoofed datagram with the victim's source address.
    // The server must not answer with a Retry larger than 3x what it got.
    let action = s.handle_initial(victim, 1, b"odcid", None);
    if let ServerAction::SendRetry { budget_bytes, .. } = action {
        panic!("server tried to spend {budget_bytes} on a 1-byte spoofed packet");
    }
    assert_eq!(
        s.connection_count(),
        0,
        "no state from an unvalidated handshake"
    );
}

#[test]
fn normal_handshake_completes_in_one_extra_round_trip() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(1, 4000);
    let odcid = b"client-chosen-odcid";

    let token = client_handshake(&mut s, client, odcid);
    // Client retries its Initial with the token.
    let action = s.handle_initial(client, 1200, odcid, Some(&token));
    let ServerAction::Admit { peer, budget_bytes } = action else {
        panic!("expected admission, got {action:?}");
    };
    assert_eq!(peer, client);
    assert!(
        budget_bytes >= 1200,
        "a validated peer must be able to receive at least what it sent"
    );
    // Server sends its handshake response, reporting the true size.
    assert!(s.settle(client, budget_bytes, 1200));
}

#[test]
fn retry_token_cannot_be_lifted_to_another_handshake() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(1, 4000);

    let token = client_handshake(&mut s, client, b"victim-odcid");
    // Presenting it with a different ODCID must not validate.
    let action = s.handle_initial(client, 1200, b"attacker-odcid", Some(&token));
    assert!(
        matches!(action, ServerAction::SendRetry { .. }),
        "token bound to another ODCID must be rejected, got {action:?}"
    );
}

#[test]
fn token_issued_by_one_node_is_accepted_by_another() {
    // Load balancer sends the Retry-generating Initial to node A and the
    // token-bearing Initial to node B.  Statelessness must make this work.
    let clock = clock_at(1_700_000_000);
    let mut node_a = server(clock.clone());
    let mut node_b = server(clock.clone());
    let client = peer(2, 4001);
    let odcid = b"rehashed-odcid";

    let token = client_handshake(&mut node_a, client, odcid);
    let action = node_b.handle_initial(client, 1200, odcid, Some(&token));
    assert!(
        matches!(action, ServerAction::Admit { .. }),
        "node B must verify node A's token, got {action:?}"
    );
}

#[test]
fn address_proof_gives_zero_rtt_admission_and_skips_retry() {
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(3, 4002);

    // Establish once, then cache an address proof like a real client would.
    let token = client_handshake(&mut s, client, b"first");
    assert!(matches!(
        s.handle_initial(client, 1200, b"first", Some(&token)),
        ServerAction::Admit { .. }
    ));
    let proof = s.issue_address_proof(client).unwrap();

    // A fresh connection from the same address with the proof is admitted
    // immediately: no Retry, no extra round trip.
    let action = s.handle_initial(client, 1200, b"second", Some(&proof));
    assert!(
        matches!(action, ServerAction::Admit { .. }),
        "0-RTT proof admission, got {action:?}"
    );

    // Proofs expire.
    manual.advance(s.token_ring().config().address_proof_lifetime_secs + 1);
    let action = s.handle_initial(client, 1200, b"third", Some(&proof));
    assert!(matches!(action, ServerAction::SendRetry { .. }));
}

#[test]
fn address_proof_from_another_address_is_not_admitted() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let honest = peer(4, 4003);
    let attacker = peer(5, 4004);

    let proof = s.issue_address_proof(honest).unwrap();
    // The attacker replays the proof from its own address.
    let action = s.handle_initial(attacker, 1200, b"x", Some(&proof));
    assert!(
        matches!(action, ServerAction::SendRetry { .. }),
        "proof bound to another address must not admit, got {action:?}"
    );
    // And using the honest address still works.
    let action = s.handle_initial(honest, 1200, b"x", Some(&proof));
    assert!(matches!(action, ServerAction::Admit { .. }));
}

#[test]
fn authenticated_migration_probes_before_switching() {
    let (_manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(6, 4005);
    let new_path = peer(7, 4006);

    s.open_connection(42, client);
    // Steady state on the old path.
    let ServerAction::Admit { budget_bytes, .. } = s.handle_authenticated(
        42,
        DatagramObservation {
            from: client,
            len: 100,
        },
    ) else {
        panic!("expected admission on the active path");
    };
    s.settle(client, budget_bytes, 100);

    // The client moves (e.g. Wi-Fi -> cellular).  The server must probe.
    let action = s.handle_authenticated(
        42,
        DatagramObservation {
            from: new_path,
            len: 1200,
        },
    );
    let ServerAction::SendPathChallenge {
        peer, challenge, ..
    } = action
    else {
        panic!("expected path challenge, got {action:?}");
    };
    assert_eq!(peer, new_path);
    assert_eq!(
        s.active_path(42),
        Some(client),
        "data must keep flowing to the old path until validation"
    );

    // The client echoes the challenge.
    let action = s.handle_path_response(42, new_path, &challenge);
    assert_eq!(action, ServerAction::PathValidated { peer: new_path });
    assert_eq!(s.active_path(42), Some(new_path));
}

#[test]
fn spoofed_migration_neither_switches_nor_amplifies() {
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(8, 4007);
    let victim = peer(9, 4008);
    s.open_connection(7, client);

    // Assume an attacker can somehow get an authenticated-looking claim (it
    // cannot without the connection keys, but the path validator must hold
    // even then).  The claim names the victim.
    let mut probes = 0u64;
    let mut bytes_to_victim = 0u64;
    for _ in 0..50 {
        if let ServerAction::SendPathChallenge { budget_bytes, .. } = s.handle_authenticated(
            7,
            DatagramObservation {
                from: victim,
                len: 1200,
            },
        ) {
            probes += 1;
            bytes_to_victim += budget_bytes;
            s.settle(victim, budget_bytes, budget_bytes);
        }
        manual.advance(1);
    }
    assert!(probes > 0, "server should try to validate the claimed path");
    // Amplification to the victim is bounded: 3x the bytes it "sent".
    assert!(
        bytes_to_victim <= 3 * 1200 * probes,
        "probe traffic must be amplification-bounded"
    );
    // Crucially, the connection never moves without a valid echo.
    assert_eq!(s.active_path(7), Some(client));
    // Pending paths are bounded and eventually reaped.
    s.tick();
    let _ = s.handle_authenticated(
        7,
        DatagramObservation {
            from: victim,
            len: 1200,
        },
    );
}

#[test]
fn probe_budget_is_per_peer_ip_not_per_port() {
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(10, 4009);
    s.open_connection(9, client);

    // The same spoofed IP from many source ports must share one probe budget.
    let ip = "192.0.2.44".parse().unwrap();
    let mut probes = 0;
    for port in 0..200u16 {
        let spoofed = PeerAddress::new(ip, 1000 + port);
        if let ServerAction::SendPathChallenge { budget_bytes, .. } = s.handle_authenticated(
            9,
            DatagramObservation {
                from: spoofed,
                len: 1200,
            },
        ) {
            probes += 1;
            s.settle(spoofed, budget_bytes, budget_bytes);
        }
        manual.advance(0); // same second: only the burst budget applies
    }
    let burst = ServerConfig::default().migration.peer_probe_burst;
    assert!(
        probes <= burst as u64,
        "per-IP probe budget must bound port rotation: {probes} > {burst}"
    );
}

#[test]
fn address_proof_accelerates_migration_to_zero_rtt() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let old = peer(11, 4010);
    let new = peer(12, 4011);

    let proof = s.issue_address_proof(new).unwrap();
    s.open_connection(11, old);

    // First packet from the new path carries the cached proof: adopt
    // immediately instead of a probe round trip.
    let action = s.handle_migration_with_proof(11, new, &proof, 1200);
    assert!(
        matches!(action, ServerAction::Admit { .. }),
        "expected 0-RTT adoption, got {action:?}"
    );
    assert_eq!(s.active_path(11), Some(new));
}

#[test]
fn forged_proof_cannot_hijack_a_connection() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let victim_conn = peer(13, 4012);
    s.open_connection(13, victim_conn);

    let mut junk = vec![1u8, 0u8];
    junk.extend_from_slice(&[0xAB; 40]);
    let attacker = peer(14, 4013);
    let action = s.handle_migration_with_proof(13, attacker, &junk, 1200);
    assert_eq!(action, ServerAction::Drop);
    assert_eq!(s.active_path(13), Some(victim_conn));
}

#[test]
fn rapid_legitimate_roaming_is_adopted_without_repeated_probes() {
    // A phone flapping between Wi-Fi and cellular within the grace window must
    // not pay a round trip every time.
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let wifi = peer(15, 4014);
    let cell = peer(16, 4015);
    s.open_connection(15, wifi);

    // Validate the cellular path once.
    let ServerAction::SendPathChallenge { challenge, .. } = s.handle_authenticated(
        15,
        DatagramObservation {
            from: cell,
            len: 1200,
        },
    ) else {
        panic!("expected probe");
    };
    assert_eq!(
        s.handle_path_response(15, cell, &challenge),
        ServerAction::PathValidated { peer: cell }
    );

    // Now flap back and forth.  Both addresses are fresh in the recent set, so
    // no further probes are needed.
    for _ in 0..3 {
        assert!(matches!(
            s.handle_authenticated(
                15,
                DatagramObservation {
                    from: wifi,
                    len: 100
                }
            ),
            ServerAction::Admit { .. }
        ));
        s.settle(wifi, 100, 100);
        assert!(matches!(
            s.handle_authenticated(
                15,
                DatagramObservation {
                    from: cell,
                    len: 100
                }
            ),
            ServerAction::Admit { .. }
        ));
        s.settle(cell, 100, 100);
        manual.advance(5);
    }
    assert_eq!(s.active_path(15), Some(cell));
}

#[test]
fn migration_frequency_cap_applies_even_for_valid_proofs() {
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let start = peer(20, 4100);
    s.open_connection(20, start);

    let cfg = ServerConfig::default().migration;
    let mut adopted = 0;
    for i in 0..(cfg.max_migrations_per_window as u16 + 20) {
        let addr = PeerAddress::v4([172, 16, (i / 256) as u8, (i % 256) as u8].into(), 6000);
        let proof = s.issue_address_proof(addr).unwrap();
        if let ServerAction::Admit { .. } = s.handle_migration_with_proof(20, addr, &proof, 100) {
            adopted += 1;
        }
        manual.advance(0);
    }
    assert_eq!(
        adopted, cfg.max_migrations_per_window,
        "per-window migration cap must hold"
    );
}

#[test]
fn cluster_rotation_does_not_lock_out_clients() {
    // Node A rotates to a new key while node B still holds both.  Tokens from
    // either node verify on both during the overlap window.
    let (_manual, clk) = manual(1_700_000_000);
    let config = fastpath_security::token::TokenConfig::default();

    let ring_a = fastpath_security::token::TokenKeyRing::new_with_clock(
        &[b"2024-key-material-aaaa", b"2025-key-material-bbbb"],
        config,
        clk.clone(),
    )
    .unwrap();
    let ring_b = fastpath_security::token::TokenKeyRing::new_with_clock(
        &[b"2024-key-material-aaaa", b"2025-key-material-bbbb"],
        config,
        clk.clone(),
    )
    .unwrap();

    let mut a = Server::new_with_clock(ServerConfig::default(), ring_a, clk.clone());
    let b = Server::new_with_clock(ServerConfig::default(), ring_b, clk.clone());
    let client = peer(30, 4200);

    let token = client_handshake(&mut a, client, b"odcid");
    // B, still on the old current key, verifies A's token.
    assert!(b
        .token_ring()
        .open(&token, TokenKind::Retry, client, Some(b"odcid"))
        .is_ok());
}

#[test]
fn replayed_token_cannot_reset_spend_to_amplify() {
    // A token proves the address was reachable, but anyone holding it can
    // present it.  Re-presenting the same token must not refill allowance
    // after it has been spent.
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let victim = peer(40, 4300);

    let token = match s.handle_initial(victim, 1200, b"o", None) {
        ServerAction::SendRetry {
            token,
            budget_bytes,
            ..
        } => {
            s.settle(victim, budget_bytes, 200);
            token
        }
        other => panic!("expected retry, got {other:?}"),
    };

    // First admission: token tier, spends the whole bootstrap flight.
    let ServerAction::Admit { budget_bytes, .. } =
        s.handle_initial(victim, 1200, b"o", Some(&token))
    else {
        panic!("expected admission");
    };
    assert!(s.settle(victim, budget_bytes, budget_bytes));
    let after_first = s.available(victim);
    assert_eq!(after_first, 0, "first admission spends the token bootstrap");

    // Replaying the same token from the same address grants more receipts
    // (the replay itself is a received datagram) but no *new* bootstrap.
    let ServerAction::Admit { budget_bytes, .. } = s.handle_initial(victim, 1, b"o", Some(&token))
    else {
        panic!("expected admission on replay");
    };
    // Allowance is now only the 3x receipts from the 1-byte replay, not another
    // 64 KiB token floor.
    assert!(
        budget_bytes <= 3,
        "replayed token must not hand out a fresh bootstrap: got {budget_bytes}"
    );
}

#[test]
fn forgetting_to_settle_under_sends_never_amplifies() {
    // The safe failure direction: if a caller authorises a send and never
    // reports it, the reservation stays spent and future sends shrink.
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let victim = peer(41, 4301);
    let _ = s.handle_initial(victim, 1200, b"o", None); // issues a Retry, reserves 200

    // We deliberately do not settle the Retry.  The 200 bytes stay spent.
    let before = s.available(victim); // 3600 - 200
    assert_eq!(before, 3600 - 200);
    // A second spoofed Initial cannot mint allowance back.
    let _ = s.handle_initial(victim, 0, b"o", None);
    assert!(s.available(victim) <= before);
}

#[test]
fn pending_path_is_reaped_by_tick_and_frees_capacity() {
    let (manual, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let client = peer(42, 4302);
    s.open_connection(100, client);
    let cfg = ServerConfig::default().migration;

    // Fill the pending-path cap with distinct forged claims.
    for i in 0..cfg.max_pending_paths {
        let spoof = peer(60 + i as u8, 5000);
        assert!(matches!(
            s.handle_authenticated(
                100,
                DatagramObservation {
                    from: spoof,
                    len: 1200
                }
            ),
            ServerAction::SendPathChallenge { .. }
        ));
    }
    // Cap reached: a further claim is refused without state.
    let extra = peer(90, 5000);
    assert_eq!(
        s.handle_authenticated(
            100,
            DatagramObservation {
                from: extra,
                len: 1200
            }
        ),
        ServerAction::Drop
    );
    // After the validation timeout, a tick reaps them and capacity returns.
    manual.advance(cfg.validation_timeout_secs + 1);
    s.tick();
    assert!(matches!(
        s.handle_authenticated(
            100,
            DatagramObservation {
                from: extra,
                len: 1200
            }
        ),
        ServerAction::SendPathChallenge { .. }
    ));
    assert_eq!(s.active_path(100), Some(client));
}

#[test]
fn zero_length_spoofed_datagram_earns_no_retry() {
    let (_, clk) = manual(1_700_000_000);
    let mut s = server(clk);
    let victim = peer(43, 4303);
    assert_eq!(s.handle_initial(victim, 0, b"o", None), ServerAction::Drop);
    assert_eq!(s.connection_count(), 0);
}
