//! Crypto tests: NIST-sized vectors are checked by length + round-trip
//! properties; known-answer checks use the fixed sizes from FIPS 203/204.
use zerotrace_core::crypto::*;

#[test]
fn mlkem_1024_sizes_and_roundtrip() {
    let (dk, ek) = mlkem_generate();
    assert_eq!(dk.len(), MLKEM_DK_LEN);
    assert_eq!(ek.len(), MLKEM_EK_LEN);
    let (ct, ss1) = mlkem_encapsulate(&ek).unwrap();
    assert_eq!(ct.len(), MLKEM_CT_LEN);
    let ss2 = mlkem_decapsulate(&dk, &ct).unwrap();
    assert_eq!(ss1, ss2);
    // Wrong key must not reproduce the secret.
    let (dk2, _) = mlkem_generate();
    let ss3 = mlkem_decapsulate(&dk2, &ct).unwrap();
    assert_ne!(ss1, ss3);
    // Bad lengths rejected.
    assert!(mlkem_encapsulate(&[0u8; 10]).is_err());
    assert!(mlkem_decapsulate(&dk, &[0u8; 10]).is_err());
}

#[test]
fn mldsa_87_sizes_and_roundtrip() {
    let (sk, pk) = mldsa_generate();
    assert_eq!(sk.len(), MLDSA_SK_LEN);
    assert_eq!(pk.len(), MLDSA_PK_LEN);
    let sig = mldsa_sign(&sk, b"test message").unwrap();
    assert_eq!(sig.len(), MLDSA_SIG_LEN);
    assert!(mldsa_verify(&pk, b"test message", &sig).is_ok());
    assert!(mldsa_verify(&pk, b"test messagf", &sig).is_err());
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 1;
    assert!(mldsa_verify(&pk, b"test message", &bad_sig).is_err());
}

#[test]
fn x25519_ed25519_and_aead() {
    let (sk_a, pk_a) = x25519_generate();
    let (sk_b, pk_b) = x25519_generate();
    assert_eq!(x25519_dh(&sk_a, &pk_b).unwrap(), x25519_dh(&sk_b, &pk_a).unwrap());
    let (esk, epk) = ed25519_generate();
    let sig = ed25519_sign(&esk, b"hello").unwrap();
    assert!(ed25519_verify(&epk, b"hello", &sig).is_ok());
    assert!(ed25519_verify(&epk, b"hellp", &sig).is_err());
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let ct = aead_encrypt(&key, &nonce, b"aad", b"secret").unwrap();
    assert_eq!(aead_decrypt(&key, &nonce, b"aad", &ct).unwrap(), b"secret");
    assert!(aead_decrypt(&key, &nonce, b"bad", &ct).is_err());
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(aead_decrypt(&key, &nonce, b"aad", &bad).is_err());
}

#[test]
fn hkdf_is_deterministic() {
    let a = hkdf_expand(b"salt", b"ikm", b"info", 32);
    let b = hkdf_expand(b"salt", b"ikm", b"info", 32);
    assert_eq!(a, b);
    assert_ne!(a, hkdf_expand(b"salt", b"ikm", b"other", 32));
}
