//! ZeroTrace-PQXDH-Sync v1 — a serverless adaptation of Signal PQXDH rev 3.
//!
//! PQXDH as specified assumes an asynchronous prekey server: Alice fetches Bob's
//! signed prekey bundle, then sends her first message without a round trip. This
//! app has no server, so the bundle is exchanged out-of-band (authenticated QR)
//! and the handshake is synchronous over the onion connection:
//!
//! 1. Both sides already hold each other's verified bundle (from QR pairing).
//! 2. Alice sends Init (ephemeral X25519 pub, ML-KEM-1024 ciphertext, her public
//!    identity, Ed25519 + ML-DSA-87 signatures over the Init).
//! 3. Bob verifies the signatures and that the claimed identity equals the bundle
//!    he verified at pairing time, decapsulates, derives SK, and replies with a
//!    confirmation (his first DH-ratchet public key + HMAC(SK, confirm)).
//! 4. Alice verifies the confirmation and both sides initialise the Double Ratchet
//!    from SK.
//!
//! Deviations from PQXDH rev 3 (documented, NOT hidden):
//! - No one-time prekey (no server to publish one); only the signed prekey is used,
//!   so DH1/DH2/DH3 use IK/SPK only.
//! - Synchronous: a round trip is required before the first message.
//! - Domain separation / info strings say `ZeroTrace-…`, not `Signal_…` / `libsignal`.
//! - ML-KEM-1024 (FIPS 203) is used, not round-3 Kyber1024.
//!
//! This construction has NOT been independently reviewed. It is EXPERIMENTAL.
use crate::crypto::*;
use crate::identity::{Identity, PublicIdentity};
use crate::ratchet::Ratchet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("ratchet: {0}")]
    Ratchet(#[from] crate::ratchet::RatchetError),
    #[error("bad message: {0}")]
    BadMessage(String),
    #[error("identity mismatch: init claims a different identity than the verified bundle")]
    IdentityMismatch,
    #[error("signature invalid")]
    BadSignature,
    #[error("confirmation invalid")]
    BadConfirmation,
}

pub type Result<T> = std::result::Result<T, HandshakeError>;

pub const INFO: &[u8] = b"ZeroTrace-PQXDH-Sync-v1";
pub const CONFIRM_MSG: &[u8] = b"ZeroTrace-responder-confirm-v1";

fn derive_sk(dh1: &[u8], dh2: &[u8], dh3: &[u8], kem_ss: &[u8]) -> [u8; 32] {
    let mut f = Vec::with_capacity(32 + 32 * 3 + kem_ss.len());
    f.extend_from_slice(&[0xFFu8; 32]);
    f.extend_from_slice(dh1);
    f.extend_from_slice(dh2);
    f.extend_from_slice(dh3);
    f.extend_from_slice(kem_ss);
    let out = hkdf_expand(&[0u8; 32], &f, INFO, 32);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&out);
    sk
}

/// Alice: build the Init message. Returns (init_bytes, sk, ephemeral secret is dropped).
pub fn initiator_init(own: &Identity, peer: &PublicIdentity) -> Result<(Vec<u8>, [u8; 32])> {
    let (ek_sk, ek_pk) = x25519_generate();
    let (ct, ss_pq) = mlkem_encapsulate(&peer.mlkem_ek)?;
    let dh1 = x25519_dh(&own.x_sk, &peer.spk_x_pk)?;
    let dh2 = x25519_dh(&ek_sk, &peer.x_pk)?;
    let dh3 = x25519_dh(&ek_sk, &peer.spk_x_pk)?;
    let sk = derive_sk(&dh1, &dh2, &dh3, &ss_pq);
    let own_pub = own.public().to_bytes();
    let mut signed_part = Vec::with_capacity(32 + MLKEM_CT_LEN + own_pub.len());
    signed_part.extend_from_slice(&ek_pk);
    signed_part.extend_from_slice(&ct);
    signed_part.extend_from_slice(&own_pub);
    let sig_ed = ed25519_sign(&own.ed_sk, &signed_part)?;
    let sig_pq = mldsa_sign(&own.mldsa_sk, &signed_part)?;
    let mut msg = Vec::with_capacity(1 + signed_part.len() + 64 + MLDSA_SIG_LEN);
    msg.push(1u8);
    msg.extend_from_slice(&signed_part);
    msg.extend_from_slice(&sig_ed);
    msg.extend_from_slice(&sig_pq);
    Ok((msg, sk))
}

/// Bob: verify Init, derive SK, build the Response (ratchet pub + HMAC confirm).
/// Returns (response_bytes, sk, responder_ratchet_keypair_secret, responder_ratchet_pub).
pub fn responder_respond(
    own: &Identity,
    peer: &PublicIdentity,
    init: &[u8],
) -> Result<(Vec<u8>, [u8; 32], Vec<u8>, Vec<u8>)> {
    let min_len = 1 + 32 + MLKEM_CT_LEN + crate::identity::PUBLIC_LEN + 64 + MLDSA_SIG_LEN;
    if init.len() != min_len { return Err(HandshakeError::BadMessage(format!("init len {}", init.len()))); }
    if init[0] != 1 { return Err(HandshakeError::BadMessage("init version".into())); }
    let mut o = 1usize;
    let ek_pk = init[o..o + 32].to_vec(); o += 32;
    let ct = init[o..o + MLKEM_CT_LEN].to_vec(); o += MLKEM_CT_LEN;
    let claimed_pub = PublicIdentity::from_bytes(&init[o..o + crate::identity::PUBLIC_LEN])
        .map_err(|e| HandshakeError::BadMessage(format!("init pub: {e}")))?;
    o += crate::identity::PUBLIC_LEN;
    let sig_ed = &init[o..o + 64]; o += 64;
    let sig_pq = &init[o..o + MLDSA_SIG_LEN];
    if claimed_pub != *peer {
        return Err(HandshakeError::IdentityMismatch);
    }
    let signed_part = &init[1..1 + 32 + MLKEM_CT_LEN + crate::identity::PUBLIC_LEN];
    ed25519_verify(&peer.ed_pk, signed_part, sig_ed).map_err(|_| HandshakeError::BadSignature)?;
    mldsa_verify(&peer.mldsa_pk, signed_part, sig_pq).map_err(|_| HandshakeError::BadSignature)?;
    let ss_pq = mlkem_decapsulate(&own.mlkem_dk, &ct)?;
    let dh1 = x25519_dh(&own.spk_x_sk, &peer.x_pk)?;
    let dh2 = x25519_dh(&own.x_sk, &ek_pk)?;
    let dh3 = x25519_dh(&own.spk_x_sk, &ek_pk)?;
    let sk = derive_sk(&dh1, &dh2, &dh3, &ss_pq);
    let (ratchet_sk, ratchet_pk) = x25519_generate();
    let mut confirm_input = Vec::with_capacity(CONFIRM_MSG.len() + 32);
    confirm_input.extend_from_slice(CONFIRM_MSG);
    confirm_input.extend_from_slice(&sha256(init));
    let confirm = hmac_sha256(&sk, &confirm_input);
    let mut resp = Vec::with_capacity(32 + 32);
    resp.extend_from_slice(&ratchet_pk);
    resp.extend_from_slice(&confirm);
    Ok((resp, sk, ratchet_sk, ratchet_pk))
}

/// Alice: verify the Response and build her ratchet. Returns the ratchet.
pub fn initiator_finish(
    own: &Identity,
    peer: &PublicIdentity,
    sk: [u8; 32],
    init: &[u8],
    response: &[u8],
) -> Result<Ratchet> {
    if response.len() != 64 {
        return Err(HandshakeError::BadMessage(format!("response len {}", response.len())));
    }
    let peer_ratchet_pk = &response[..32];
    let confirm = &response[32..];
    let mut confirm_input = Vec::with_capacity(CONFIRM_MSG.len() + 32);
    confirm_input.extend_from_slice(CONFIRM_MSG);
    confirm_input.extend_from_slice(&sha256(init));
    let expected = hmac_sha256(&sk, &confirm_input);
    if confirm != expected.as_slice() {
        return Err(HandshakeError::BadConfirmation);
    }
    Ok(Ratchet::new_initiator(sk, peer_ratchet_pk, &peer.mlkem_ek, &own.mlkem_dk)?)
}

/// Bob: build his ratchet after responding.
pub fn responder_ratchet(
    own: &Identity,
    peer: &PublicIdentity,
    sk: [u8; 32],
    ratchet_sk: Vec<u8>,
    ratchet_pk: Vec<u8>,
) -> Result<Ratchet> {
    Ok(Ratchet::new_responder(sk, ratchet_sk, ratchet_pk, &peer.mlkem_ek, &own.mlkem_dk)?)
}
