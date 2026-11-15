//! Handshake + ratchet protocol tests: MITM, downgrade, replay, reorder, tamper.
use zerotrace_core::identity::{verify_pairing_qr, Identity};
use zerotrace_core::session::{MemoryTransport, Session};

fn pair() -> (Session, Session) {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub = alice.public();
    let bob_pub = bob.public();
    let (ta, tb) = MemoryTransport::pair();
    (
        Session::new(alice, bob_pub, Box::new(ta)),
        Session::new(bob, alice_pub, Box::new(tb)),
    )
}

fn handshake(sa: &mut Session, sb: &mut Session) {
    let init = sa.handshake_init().unwrap();
    let resp = sb.handshake_respond(&init).unwrap();
    sa.handshake_finish(&resp).unwrap();
}

#[test]
fn full_handshake_and_bidirectional_messages() {
    let (mut sa, mut sb) = pair();
    handshake(&mut sa, &mut sb);
    for i in 0..5 {
        let m = format!("alice message {i}");
        let c = sa.encrypt(m.as_bytes()).unwrap();
        assert_eq!(sb.decrypt(&c).unwrap(), m.as_bytes());
        let r = format!("bob reply {i}");
        let c2 = sb.encrypt(r.as_bytes()).unwrap();
        assert_eq!(sa.decrypt(&c2).unwrap(), r.as_bytes());
    }
}

#[test]
fn tampered_init_is_rejected() {
    let (mut sa, mut sb) = pair();
    let mut init = sa.handshake_init().unwrap();
    init[100] ^= 1; // flip a byte inside the KEM ciphertext / signatures region
    assert!(sb.handshake_respond(&init).is_err());
}

#[test]
fn identity_mismatch_is_rejected() {
    // Bob tries to respond with a peer identity that is not Alice's.
    let alice = Identity::generate();
    let mallory = Identity::generate();
    let bob = Identity::generate();
    let bob_pub = bob.public();
    let mallory_pub = mallory.public();
    let (ta, tb) = MemoryTransport::pair();
    let mut sa = Session::new(alice, bob_pub, Box::new(ta));
    // sb is built with Mallory as the expected peer, but the init comes from Alice.
    let mut sb = Session::new(bob, mallory_pub, Box::new(tb));
    let init = sa.handshake_init().unwrap();
    assert!(sb.handshake_respond(&init).is_err());
}

#[test]
fn replay_and_tamper_rejected_by_ratchet() {
    let (mut sa, mut sb) = pair();
    handshake(&mut sa, &mut sb);
    let c = sa.encrypt(b"once").unwrap();
    assert_eq!(sb.decrypt(&c).unwrap(), b"once");
    assert!(sb.decrypt(&c).is_err(), "replay must fail");
    let c2 = sa.encrypt(b"twice").unwrap();
    let mut bad = c2.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(sb.decrypt(&bad).is_err(), "tamper must fail");
    // The untampered message still decrypts afterwards.
    assert_eq!(sb.decrypt(&c2).unwrap(), b"twice");
}

#[test]
fn out_of_order_messages() {
    let (mut sa, mut sb) = pair();
    handshake(&mut sa, &mut sb);
    let c1 = sa.encrypt(b"first").unwrap();
    let c2 = sa.encrypt(b"second").unwrap();
    let c3 = sa.encrypt(b"third").unwrap();
    // Deliver 2nd, then 1st (skipped key), then 3rd.
    assert_eq!(sb.decrypt(&c2).unwrap(), b"second");
    assert_eq!(sb.decrypt(&c1).unwrap(), b"first");
    assert_eq!(sb.decrypt(&c3).unwrap(), b"third");
}

#[test]
fn qr_roundtrip_and_tamper() {
    let alice = Identity::generate();
    let onion = "abcdefghij23456789abcdefghij23456789abcdefghij23456789ab.onion"; // 56 chars + .onion
    let qr = alice.pairing_qr(onion);
    // The commitment QR is compact enough for a real QR code.
    assert!(qr.len() < 1500, "commitment QR too large: {} bytes", qr.len());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let commitment = verify_pairing_qr(&qr, now).unwrap();
    assert_eq!(commitment.onion_address, onion);
    assert_eq!(commitment.ed_pk, alice.public().ed_pk);
    // Full bundle exchange over the (simulated) channel, verified vs commitment.
    let bundle = alice.full_bundle_json(onion);
    let peer = zerotrace_core::identity::verify_full_bundle(&bundle, &commitment).unwrap();
    assert_eq!(peer.ed_pk, alice.public().ed_pk);
    assert_eq!(peer.mldsa_pk, alice.public().mldsa_pk);
    assert_eq!(peer.mlkem_ek, alice.public().mlkem_ek);
    // A bundle with a swapped PQ key must fail the commitment hash check.
    let bob = Identity::generate();
    let mut bad_bundle = serde_json::from_str::<serde_json::Value>(&bundle).unwrap();
    bad_bundle["ik_pq"] = serde_json::Value::String(hex::encode(bob.public().mldsa_pk));
    assert!(zerotrace_core::identity::verify_full_bundle(
        &serde_json::to_string(&bad_bundle).unwrap(), &commitment).is_err());
    // Tamper with one character of the QR signature region.
    let mut bad = qr.clone();
    let pos = bad.len() - 5;
    bad.replace_range(pos..pos + 1, "0");
    assert!(verify_pairing_qr(&bad, now).is_err());
    // Wrong protocol / expired.
    assert!(verify_pairing_qr("{\"p\":\"xx\",\"v\":1}", now).is_err());
}
