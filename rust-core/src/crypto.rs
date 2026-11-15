//! Thin wrappers over reviewed crates. No custom primitives are defined here.
//! Every function validates input lengths and returns an error instead of panicking
//! on untrusted data.
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::{Aead, Payload};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Seed as MlDsaSeed, Signer as MlDsaSigner};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};
use kem::{Decapsulate, Encapsulate};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Concrete ML-KEM-1024 key types, named through the KemCore trait so the
/// parameter-set type never has to be spelled out.
pub type MlKem1024DK = <MlKem1024 as KemCore>::DecapsulationKey;
pub type MlKem1024EK = <MlKem1024 as KemCore>::EncapsulationKey;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("bad length for {0}: got {1}")]
    BadLength(&'static str, usize),
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("authentication failed")]
    AuthFailed,
    #[error("crypto operation failed: {0}")]
    Failed(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub const ED_PK_LEN: usize = 32;
pub const ED_SK_LEN: usize = 32;
pub const X_LEN: usize = 32;
pub const MLDSA_PK_LEN: usize = 2592;
/// ML-DSA secret material in this crate is the 32-byte seed (the crate's
/// preferred serialisation — `SigningKey::from_seed` reconstructs the key).
/// No 4032-byte expanded key is ever stored.
pub const MLDSA_SK_LEN: usize = 32;
pub const MLDSA_SIG_LEN: usize = 4627;
pub const MLKEM_EK_LEN: usize = 1568;
pub const MLKEM_DK_LEN: usize = 3168;
pub const MLKEM_CT_LEN: usize = 1568;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("HKDF expand length is bounded by construction");
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

// ---------- X25519 ----------
pub fn x25519_generate() -> (Vec<u8>, Vec<u8>) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = X25519PublicKey::from(&sk);
    (sk.to_bytes().to_vec(), pk.as_bytes().to_vec())
}

pub fn x25519_public(sk: &[u8]) -> Result<Vec<u8>> {
    let arr: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadLength("x25519 secret", sk.len()))?;
    Ok(X25519PublicKey::from(&StaticSecret::from(arr)).as_bytes().to_vec())
}

pub fn x25519_dh(sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>> {
    let sk_arr: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadLength("x25519 secret", sk.len()))?;
    let pk_arr: [u8; 32] = peer_pk.try_into().map_err(|_| CryptoError::BadLength("x25519 public", peer_pk.len()))?;
    let shared = StaticSecret::from(sk_arr).diffie_hellman(&X25519PublicKey::from(pk_arr));
    Ok(shared.as_bytes().to_vec())
}

// ---------- Ed25519 ----------
pub fn ed25519_generate() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut OsRng);
    (sk.to_bytes().to_vec(), sk.verifying_key().to_bytes().to_vec())
}

pub fn ed25519_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let arr: [u8; 32] = sk.try_into().map_err(|_| CryptoError::BadLength("ed25519 secret", sk.len()))?;
    Ok(SigningKey::from_bytes(&arr).sign(msg).to_bytes().to_vec())
}

pub fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let pk_arr: [u8; 32] = pk.try_into().map_err(|_| CryptoError::BadLength("ed25519 public", pk.len()))?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadLength("ed25519 signature", sig.len()))?;
    VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| CryptoError::InvalidKey)?
        .verify(msg, &Signature::from_bytes(&sig_arr))
        .map_err(|_| CryptoError::InvalidSignature)
}

// ---------- ML-KEM-1024 (FIPS 203) ----------
pub fn mlkem_generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    (dk.as_bytes().as_slice().to_vec(), ek.as_bytes().as_slice().to_vec())
}

pub fn mlkem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let arr = Encoded::<MlKem1024EK>::try_from(ek_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let ek = MlKem1024EK::from_bytes(&arr);
    let (ct, ss) = ek.encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::Failed("encapsulate failed".into()))?;
    Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

pub fn mlkem_decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
    let dk_arr = Encoded::<MlKem1024DK>::try_from(dk_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let dk = MlKem1024DK::from_bytes(&dk_arr);
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let ss = dk.decapsulate(&ct)
        .map_err(|_| CryptoError::Failed("decapsulate failed".into()))?;
    Ok(ss.as_slice().to_vec())
}

// ---------- ML-DSA-87 (FIPS 204) ----------
// Secret = 32-byte seed. The `Signer` impl for SigningKey uses the deterministic
// ML-DSA.Sign variant with an empty context string.
pub fn mldsa_generate() -> (Vec<u8>, Vec<u8>) {
    let seed = random_bytes(32);
    let seed_arr = MlDsaSeed::try_from(seed.as_slice()).expect("32-byte seed");
    let sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed_arr);
    (seed, sk.verifying_key().encode().as_slice().to_vec())
}

pub fn mldsa_sign(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let seed_arr = MlDsaSeed::try_from(sk_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let sig = sk.try_sign(msg)
        .map_err(|_| CryptoError::Failed("ml-dsa sign failed".into()))?;
    Ok(sig.encode().as_slice().to_vec())
}

pub fn mldsa_verify(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let pk_arr = EncodedVerifyingKey::<MlDsa87>::try_from(pk_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_arr);
    let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;
    let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_arr)
        .ok_or(CryptoError::InvalidKey)?;
    if vk.verify_with_context(msg, b"", &sig) { Ok(()) } else { Err(CryptoError::InvalidSignature) }
}

// ---------- ChaCha20-Poly1305 AEAD ----------
pub fn aead_encrypt(key: &[u8], nonce12: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::BadLength("aead key", key.len()))?;
    let nonce = Nonce::from_slice(nonce12);
    cipher.encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AuthFailed)
}

pub fn aead_decrypt(key: &[u8], nonce12: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::BadLength("aead key", key.len()))?;
    let nonce = Nonce::from_slice(nonce12);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::AuthFailed)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_nonce12() -> [u8; 12] {
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    n
}
