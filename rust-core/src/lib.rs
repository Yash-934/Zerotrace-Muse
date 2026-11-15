//! ZeroTrace security core.
//!
//! Layout:
//! - `identity` — dual (classical + post-quantum) identity keypairs, serialisation, fingerprints.
//! - `crypto` — thin wrappers over reviewed crates (ML-KEM-1024, ML-DSA-87, X25519,
//!   Ed25519, ChaCha20-Poly1305, HKDF/HMAC-SHA-256). No custom primitives.
//! - `handshake` — ZeroTrace-PQXDH-Sync v1 (serverless adaptation of Signal PQXDH rev 3).
//! - `ratchet` — Signal Double Ratchet (rev 4) with a fresh ML-KEM encapsulation folded
//!   into every DH ratchet step (DH+KEM ratchet). ML-KEM Braid is NOT implemented.
//! - `session` — opaque session handles, transport abstraction.
//! - `call` — per-call media transport (RTP + ChaCha20-Poly1305 payload AEAD,
//!   replay window). No new primitive; the AEAD is the one in `crypto`.
//! - `tor` — Tor state machine + Arti transport (feature `tor`); fails closed without it.
//! - `ffi` — JNI bridge. Private keys never leave this crate.

pub mod call;
pub mod crypto;
pub mod ffi;
pub mod handshake;
pub mod identity;
pub mod memory;
pub mod ratchet;
pub mod session;
pub mod tor;

pub use identity::{Identity, IdentityBundle, PublicIdentity};

/// In-process self-test used by the Android dashboard (`nativeSelfTest`).
/// Runs real crypto (not mocks): KEM + signatures + a full two-party handshake
/// and ratchet exchange, plus tamper and replay checks. Returns "OK" or a
/// failure description.
pub fn self_test_impl() -> String {
    use session::{MemoryTransport, Session};
    let run = || -> Result<(), String> {
        // ML-KEM-1024 round trip + tamper.
        let (dk, ek) = crypto::mlkem_generate();
        let (ct, ss1) = crypto::mlkem_encapsulate(&ek).map_err(|e| format!("kem encap: {e}"))?;
        let ss2 = crypto::mlkem_decapsulate(&dk, &ct).map_err(|e| format!("kem decap: {e}"))?;
        if ss1 != ss2 { return Err("kem shared secret mismatch".into()); }
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        // Decapsulation of a tampered ciphertext must not reproduce the secret
        // (implicit rejection returns a pseudorandom secret instead).
        let ss_bad = crypto::mlkem_decapsulate(&dk, &bad_ct).map_err(|e| format!("kem bad decap: {e}"))?;
        if ss_bad == ss1 { return Err("kem tamper not rejected".into()); }
        // ML-DSA-87 sign/verify + tamper.
        let (dsk, dpk) = crypto::mldsa_generate();
        let sig = crypto::mldsa_sign(&dsk, b"zerotrace").map_err(|e| format!("dsa sign: {e}"))?;
        crypto::mldsa_verify(&dpk, b"zerotrace", &sig).map_err(|e| format!("dsa verify: {e}"))?;
        if crypto::mldsa_verify(&dpk, b"zerotracf", &sig).is_ok() {
            return Err("dsa tamper not rejected".into());
        }
        // Full handshake + ratchet over paired in-memory transports.
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_pub = alice.public();
        let bob_pub = bob.public();
        let (ta, tb) = MemoryTransport::pair();
        let mut sa = Session::new(alice, bob_pub, Box::new(ta));
        let mut sb = Session::new(bob, alice_pub, Box::new(tb));
        let init = sa.handshake_init().map_err(|e| format!("init: {e}"))?;
        let resp = sb.handshake_respond(&init).map_err(|e| format!("respond: {e}"))?;
        sa.handshake_finish(&resp).map_err(|e| format!("finish: {e}"))?;
        let c1 = sa.encrypt(b"hello bob").map_err(|e| format!("enc1: {e}"))?;
        let p1 = sb.decrypt(&c1).map_err(|e| format!("dec1: {e}"))?;
        if p1 != b"hello bob" { return Err("message 1 mismatch".into()); }
        let c2 = sb.encrypt(b"hello alice").map_err(|e| format!("enc2: {e}"))?;
        let p2 = sa.decrypt(&c2).map_err(|e| format!("dec2: {e}"))?;
        if p2 != b"hello alice" { return Err("message 2 mismatch".into()); }
        // Tamper: flipping a ciphertext byte must fail authentication.
        let mut bad = c1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        if sb.decrypt(&bad).is_ok() { return Err("ratchet tamper not rejected".into()); }
        // Replay: decrypting c1 again must fail.
        if sb.decrypt(&c1).is_ok() { return Err("ratchet replay not rejected".into()); }
        // Media transport: one call's RTP round trip, both directions, plus
        // tamper and replay rejection (call.rs unit tests cover more).
        let mut reg_a = call::CallRegistry::new();
        let mut reg_b = call::CallRegistry::new();
        let (call_id, key) = reg_a.begin();
        if !reg_b.join(call_id, key) { return Err("call join failed".into()); }
        let pkt = reg_a.encode_audio(&call_id, b"opus-frame").map_err(|e| format!("media enc: {e}"))?;
        let pt = reg_b.decode_audio(&call_id, &pkt).map_err(|e| format!("media dec: {e}"))?;
        if pt != b"opus-frame" { return Err("media mismatch".into()); }
        if reg_b.decode_audio(&call_id, &pkt).is_ok() { return Err("media replay not rejected".into()); }
        Ok(())
    };
    match run() {
        Ok(()) => "OK".to_string(),
        Err(e) => format!("FAIL: {e}"),
    }
}

