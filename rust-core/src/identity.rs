//! Dual identity: classical (Ed25519 signing + X25519 agreement) and
//! post-quantum (ML-DSA-87 signing + ML-KEM-1024 prekey).
//!
//! Bundle wire format (version 1, fixed offsets, all lengths checked on parse):
//! ```text
//! [0]     version = 1
//! [1..33]   ed25519 secret key
//! [33..65]  ed25519 public key
//! [65..97]  x25519 identity secret key
//! [97..129] x25519 identity public key
//! [129..161]  ml-dsa-87 signing key seed (32)
//! [161..2753] ml-dsa-87 verifying key (2592)
//! [2753..5921] ml-kem-1024 decapsulation key (3168)
//! [5921..7489] ml-kem-1024 encapsulation key (1568)
//! [7489..7521] x25519 signed-prekey secret (32)
//! [7521..7553] x25519 signed-prekey public (32)
//! ```
//! Total: 7553 bytes. The public identity is the same layout minus the secrets.
use crate::crypto::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const BUNDLE_LEN: usize = 7553;
pub const PUBLIC_LEN: usize = 32 + 32 + 2592 + 1568 + 32; // ed_pk + x_pk + mldsa_pk + mlkem_ek + spk_pk

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("bad bundle length: {0}")]
    BadLength(usize),
    #[error("bad version: {0}")]
    BadVersion(u8),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("qr: {0}")]
    Qr(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

/// Secret identity material. Zeroed on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Identity {
    pub ed_sk: Vec<u8>,
    pub ed_pk: Vec<u8>,
    pub x_sk: Vec<u8>,
    pub x_pk: Vec<u8>,
    pub mldsa_sk: Vec<u8>,
    pub mldsa_pk: Vec<u8>,
    pub mlkem_dk: Vec<u8>,
    pub mlkem_ek: Vec<u8>,
    pub spk_x_sk: Vec<u8>,
    pub spk_x_pk: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Self {
        let (ed_sk, ed_pk) = ed25519_generate();
        let (x_sk, x_pk) = x25519_generate();
        let (mldsa_sk, mldsa_pk) = mldsa_generate();
        let (mlkem_dk, mlkem_ek) = mlkem_generate();
        let (spk_x_sk, spk_x_pk) = x25519_generate();
        Identity { ed_sk, ed_pk, x_sk, x_pk, mldsa_sk, mldsa_pk, mlkem_dk, mlkem_ek, spk_x_sk, spk_x_pk }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            ed_pk: self.ed_pk.clone(),
            x_pk: self.x_pk.clone(),
            mldsa_pk: self.mldsa_pk.clone(),
            mlkem_ek: self.mlkem_ek.clone(),
            spk_x_pk: self.spk_x_pk.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_LEN);
        out.push(1u8);
        out.extend_from_slice(&self.ed_sk);
        out.extend_from_slice(&self.ed_pk);
        out.extend_from_slice(&self.x_sk);
        out.extend_from_slice(&self.x_pk);
        out.extend_from_slice(&self.mldsa_sk);
        out.extend_from_slice(&self.mldsa_pk);
        out.extend_from_slice(&self.mlkem_dk);
        out.extend_from_slice(&self.mlkem_ek);
        out.extend_from_slice(&self.spk_x_sk);
        out.extend_from_slice(&self.spk_x_pk);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != BUNDLE_LEN { return Err(IdentityError::BadLength(b.len())); }
        if b[0] != 1 { return Err(IdentityError::BadVersion(b[0])); }
        let mut o = 1usize;
        let mut take = |n: usize| -> Vec<u8> { let s = b[o..o + n].to_vec(); o += n; s };
        Ok(Identity {
            ed_sk: take(ED_SK_LEN), ed_pk: take(ED_PK_LEN),
            x_sk: take(X_LEN), x_pk: take(X_LEN),
            mldsa_sk: take(MLDSA_SK_LEN), mldsa_pk: take(MLDSA_PK_LEN),
            mlkem_dk: take(MLKEM_DK_LEN), mlkem_ek: take(MLKEM_EK_LEN),
            spk_x_sk: take(X_LEN), spk_x_pk: take(X_LEN),
        })
    }
}

/// Everything a peer needs to verify and contact us. No secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    #[serde(with = "hex_serde")]
    pub ed_pk: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub x_pk: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub mldsa_pk: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub mlkem_ek: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub spk_x_pk: Vec<u8>,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl PublicIdentity {
    /// Fingerprint: SHA-256 over the two identity public keys, 12 groups of 4 hex chars.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.ed_pk);
        h.update(&self.mldsa_pk);
        let digest = h.finalize();
        let hexed = hex::encode(&digest[..24]);
        hexed.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>().join(" ")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_LEN);
        out.extend_from_slice(&self.ed_pk);
        out.extend_from_slice(&self.x_pk);
        out.extend_from_slice(&self.mldsa_pk);
        out.extend_from_slice(&self.mlkem_ek);
        out.extend_from_slice(&self.spk_x_pk);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PUBLIC_LEN { return Err(IdentityError::BadLength(b.len())); }
        let mut o = 0usize;
        let mut take = |n: usize| -> Vec<u8> { let s = b[o..o + n].to_vec(); o += n; s };
        Ok(PublicIdentity {
            ed_pk: take(ED_PK_LEN), x_pk: take(X_LEN),
            mldsa_pk: take(MLDSA_PK_LEN), mlkem_ek: take(MLKEM_EK_LEN),
            spk_x_pk: take(X_LEN),
        })
    }
}

pub type IdentityBundle = Identity;

/// A verified pairing bundle from a QR code, plus the peer's onion address.
///
/// WHY A COMMITMENT, NOT THE FULL KEYS: a QR code cannot hold post-quantum
/// keys. ML-DSA-87's public key alone is 2592 bytes and its signature 4627
/// bytes — far beyond QR capacity (~3 KB). So the QR carries a compact
/// *commitment*: the classical identity keys in full, plus SHA-256 hashes of
/// the two post-quantum public keys, all signed with Ed25519. The full PQ keys
/// are exchanged afterwards over the Tor channel and verified against these
/// hashes (see `full_bundle_json` / `verify_full_bundle`). A peer that presents
/// different PQ keys than the QR committed to is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub onion_address: String,
    pub ed_pk: Vec<u8>,
    pub x_pk: Vec<u8>,
    pub spk_x_pk: Vec<u8>,
    pub mldsa_pk_hash: Vec<u8>, // SHA-256 of the ML-DSA-87 verifying key
    pub mlkem_ek_hash: Vec<u8>, // SHA-256 of the ML-KEM-1024 encapsulation key
    pub expiry_epoch_seconds: u64,
    pub nonce: Vec<u8>,
}

impl Commitment {
    /// The fingerprint users compare: SHA-256 over the classical identity key,
    /// the two PQ-key hashes and the onion address — computable from the QR alone.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.ed_pk);
        h.update(&self.mldsa_pk_hash);
        h.update(&self.mlkem_ek_hash);
        h.update(self.onion_address.as_bytes());
        let digest = h.finalize();
        let hexed = hex::encode(&digest[..24]);
        hexed.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>().join(" ")
    }
}

/// Backwards-compatible name for the verified pairing result.
pub type VerifiedPeer = Commitment;

/// Canonical bytes that the QR signature covers: the JSON object of the
/// unsigned commitment fields, serialised by serde_json (keys sorted).
fn canonical_commitment(c: &Commitment) -> String {
    let obj = serde_json::json!({
        "p": "zt", "v": 1,
        "onion": c.onion_address,
        "ik_ed": hex::encode(&c.ed_pk),
        "ik_x": hex::encode(&c.x_pk),
        "spk_x": hex::encode(&c.spk_x_pk),
        "pq_id_hash": hex::encode(&c.mldsa_pk_hash),
        "pq_ek_hash": hex::encode(&c.mlkem_ek_hash),
        "exp": c.expiry_epoch_seconds,
        "nonce": hex::encode(&c.nonce),
        "caps": ["pqxdh-sync-v1", "dr-chacha-v1"],
    });
    serde_json::to_string(&obj).expect("canonical JSON serialisation cannot fail")
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

impl Identity {
    /// Build the pairing QR JSON (a commitment, ~700 bytes — fits a QR code).
    /// Valid 10 minutes.
    pub fn pairing_qr(&self, onion_address: &str) -> String {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) + 600;
        let c = Commitment {
            onion_address: onion_address.to_string(),
            ed_pk: self.ed_pk.clone(),
            x_pk: self.x_pk.clone(),
            spk_x_pk: self.spk_x_pk.clone(),
            mldsa_pk_hash: sha256_bytes(&self.mldsa_pk),
            mlkem_ek_hash: sha256_bytes(&self.mlkem_ek),
            expiry_epoch_seconds: expiry,
            nonce: random_bytes(16),
        };
        let canon = canonical_commitment(&c);
        let sig_ed = ed25519_sign(&self.ed_sk, canon.as_bytes())
            .expect("ed25519 signing of own commitment cannot fail");
        let mut obj = serde_json::from_str::<serde_json::Value>(&canon)
            .expect("canonical JSON parses");
        obj["sig_ed"] = serde_json::Value::String(hex::encode(sig_ed));
        serde_json::to_string(&obj).expect("qr JSON serialisation cannot fail")
    }

    /// The full public bundle, exchanged over the Tor channel after pairing and
    /// verified against the QR commitment. Contains the real PQ keys plus both
    /// signatures over the canonical full bundle.
    pub fn full_bundle_json(&self, onion_address: &str) -> String {
        let pub_id = self.public();
        let obj = serde_json::json!({
            "kind": "zerotrace-full-bundle-v1",
            "onion": onion_address,
            "ik_ed": hex::encode(&pub_id.ed_pk),
            "ik_x": hex::encode(&pub_id.x_pk),
            "ik_pq": hex::encode(&pub_id.mldsa_pk),
            "spk_x": hex::encode(&pub_id.spk_x_pk),
            "pq_pk": hex::encode(&pub_id.mlkem_ek),
        });
        let canon = serde_json::to_string(&obj).expect("bundle JSON cannot fail");
        let sig_ed = ed25519_sign(&self.ed_sk, canon.as_bytes())
            .expect("ed25519 signing of own bundle cannot fail");
        let sig_pq = mldsa_sign(&self.mldsa_sk, canon.as_bytes())
            .expect("ml-dsa signing of own bundle cannot fail");
        let mut obj = serde_json::from_str::<serde_json::Value>(&canon)
            .expect("canonical JSON parses");
        obj["sig_ed"] = serde_json::Value::String(hex::encode(sig_ed));
        obj["sig_pq"] = serde_json::Value::String(hex::encode(sig_pq));
        serde_json::to_string(&obj).expect("bundle JSON serialisation cannot fail")
    }
}

/// Parse and fully verify a pairing QR: structure, lengths, version, expiry,
/// capabilities, and the Ed25519 signature over the commitment. Returns the
/// commitment or an error — never a partially-trusted bundle.
pub fn verify_pairing_qr(raw: &str, now_epoch_seconds: u64) -> Result<Commitment> {
    if raw.len() > 8192 { return Err(IdentityError::Qr("qr too large".into())); }
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| IdentityError::Qr(format!("not JSON: {e}")))?;
    let get = |k: &str| -> Result<String> {
        v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
            .ok_or_else(|| IdentityError::Qr(format!("missing {k}")))
    };
    if get("p")? != "zt" { return Err(IdentityError::Qr("unknown protocol".into())); }
    if v.get("v").and_then(|x| x.as_u64()) != Some(1) {
        return Err(IdentityError::Qr("unsupported version".into()));
    }
    let onion = get("onion")?;
    if !onion.ends_with(".onion") || onion.len() != 62 {
        return Err(IdentityError::Qr("bad onion address".into()));
    }
    let expiry = v.get("exp").and_then(|x| x.as_u64())
        .ok_or_else(|| IdentityError::Qr("missing exp".into()))?;
    if expiry <= now_epoch_seconds { return Err(IdentityError::Qr("pairing QR expired".into())); }
    if expiry - now_epoch_seconds > 660 {
        return Err(IdentityError::Qr("expiry too far in future".into()));
    }
    let hex_field = |k: &str, n: usize| -> Result<Vec<u8>> {
        let s = get(k)?;
        let b = hex::decode(&s).map_err(|_| IdentityError::Qr(format!("bad hex {k}")))?;
        if b.len() != n { return Err(IdentityError::Qr(format!("bad length {k}"))); }
        Ok(b)
    };
    let c = Commitment {
        onion_address: onion,
        ed_pk: hex_field("ik_ed", ED_PK_LEN)?,
        x_pk: hex_field("ik_x", X_LEN)?,
        spk_x_pk: hex_field("spk_x", X_LEN)?,
        mldsa_pk_hash: hex_field("pq_id_hash", 32)?,
        mlkem_ek_hash: hex_field("pq_ek_hash", 32)?,
        expiry_epoch_seconds: expiry,
        nonce: hex_field("nonce", 16)?,
    };
    let caps = v.get("caps").and_then(|x| x.as_array())
        .ok_or_else(|| IdentityError::Qr("missing caps".into()))?;
    let cap_strs: Vec<&str> = caps.iter().filter_map(|x| x.as_str()).collect();
    if !cap_strs.contains(&"pqxdh-sync-v1") {
        return Err(IdentityError::Qr("peer lacks pqxdh-sync-v1".into()));
    }
    let sig_ed = hex_field("sig_ed", 64)?;
    let canon = canonical_commitment(&c);
    ed25519_verify(&c.ed_pk, canon.as_bytes(), &sig_ed)
        .map_err(|_| IdentityError::Qr("ed25519 commitment signature invalid".into()))?;
    Ok(c)
}

/// Verify a full bundle received over the Tor channel against the QR
/// commitment: the PQ-key hashes must match, the classical keys must match,
/// and BOTH signatures (Ed25519 + ML-DSA-87) over the canonical bundle must
/// verify. Returns the peer's full public identity.
pub fn verify_full_bundle(raw: &str, commitment: &Commitment) -> Result<PublicIdentity> {
    if raw.len() > 65536 { return Err(IdentityError::Qr("bundle too large".into())); }
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| IdentityError::Qr(format!("not JSON: {e}")))?;
    let get = |k: &str| -> Result<String> {
        v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
            .ok_or_else(|| IdentityError::Qr(format!("missing {k}")))
    };
    if get("kind")? != "zerotrace-full-bundle-v1" {
        return Err(IdentityError::Qr("unknown bundle kind".into()));
    }
    if get("onion")? != commitment.onion_address {
        return Err(IdentityError::Qr("bundle onion does not match commitment".into()));
    }
    let hex_field = |k: &str, n: usize| -> Result<Vec<u8>> {
        let s = get(k)?;
        let b = hex::decode(&s).map_err(|_| IdentityError::Qr(format!("bad hex {k}")))?;
        if b.len() != n { return Err(IdentityError::Qr(format!("bad length {k}"))); }
        Ok(b)
    };
    let id = PublicIdentity {
        ed_pk: hex_field("ik_ed", ED_PK_LEN)?,
        x_pk: hex_field("ik_x", X_LEN)?,
        mldsa_pk: hex_field("ik_pq", MLDSA_PK_LEN)?,
        spk_x_pk: hex_field("spk_x", X_LEN)?,
        mlkem_ek: hex_field("pq_pk", MLKEM_EK_LEN)?,
    };
    if id.ed_pk != commitment.ed_pk || id.x_pk != commitment.x_pk
        || id.spk_x_pk != commitment.spk_x_pk {
        return Err(IdentityError::Qr("bundle classical keys do not match commitment".into()));
    }
    if sha256_bytes(&id.mldsa_pk) != commitment.mldsa_pk_hash {
        return Err(IdentityError::Qr("ml-dsa key does not match commitment hash".into()));
    }
    if sha256_bytes(&id.mlkem_ek) != commitment.mlkem_ek_hash {
        return Err(IdentityError::Qr("ml-kem key does not match commitment hash".into()));
    }
    let sig_ed = hex_field("sig_ed", 64)?;
    let sig_pq = hex_field("sig_pq", MLDSA_SIG_LEN)?;
    let obj = serde_json::json!({
        "kind": "zerotrace-full-bundle-v1",
        "onion": commitment.onion_address,
        "ik_ed": hex::encode(&id.ed_pk),
        "ik_x": hex::encode(&id.x_pk),
        "ik_pq": hex::encode(&id.mldsa_pk),
        "spk_x": hex::encode(&id.spk_x_pk),
        "pq_pk": hex::encode(&id.mlkem_ek),
    });
    let canon = serde_json::to_string(&obj).expect("bundle JSON cannot fail");
    ed25519_verify(&id.ed_pk, canon.as_bytes(), &sig_ed)
        .map_err(|_| IdentityError::Qr("ed25519 bundle signature invalid".into()))?;
    mldsa_verify(&id.mldsa_pk, canon.as_bytes(), &sig_pq)
        .map_err(|_| IdentityError::Qr("ml-dsa bundle signature invalid".into()))?;
    Ok(id)
}
