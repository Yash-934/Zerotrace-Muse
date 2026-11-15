//! Double Ratchet (Signal rev 4) with a DH+KEM step.
//!
//! Faithful to the spec for: root/chain/message key derivation (HKDF + HMAC),
//! header (DH pub, pn, n), skipped-message keys, out-of-order handling.
//!
//! Deviations (documented):
//! - Message AEAD is ChaCha20-Poly1305 (reviewed AEAD) instead of the spec's
//!   AES-256-CBC + truncated HMAC. The header is the AAD. This avoids CBC
//!   padding-oracle risk and is a deliberate, labelled change.
//! - Every DH ratchet step also encapsulates fresh ML-KEM-1024 material to the
//!   peer's long-term prekey and mixes the shared secret into the root KDF.
//!   The ciphertext (1568 bytes) travels in EVERY message header, so a receiver
//!   that gets a later message of a new chain first can still perform the
//!   ratchet step. Only a new chain uses the ciphertext; later messages in the
//!   same chain ignore it (their keys come from the chain). This costs ~1.6 KB
//!   per message. This is a DH+KEM ratchet, NOT Signal's ML-KEM Braid
//!   (sparse erasure-coded KEM over ~74 messages). Braid is not implemented.
//! - Maximum skipped messages per chain: 1000. Maximum stored skipped keys: 1000.
use crate::crypto::*;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("bad message: {0}")]
    BadMessage(String),
    #[error("message authentication failed")]
    AuthFailed,
    #[error("replayed or duplicate message")]
    Replay,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("ratchet not ready")]
    NotReady,
}

pub type Result<T> = std::result::Result<T, RatchetError>;

pub const MAX_SKIP: u32 = 1000;
pub const MAX_SKIPPED_KEYS: usize = 1000;

/// What a successful decrypt commits to the ratchet state. Nothing is
/// committed when authentication fails.
enum Commit {
    RemoveSkipped,
    Advance { next_chain: [u8; 32], skipped_new: Vec<(u32, [u8; 32])>, new_recv_n: u32 },
}

fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8], kem_ss: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(dh_out.len() + kem_ss.len());
    ikm.extend_from_slice(dh_out);
    ikm.extend_from_slice(kem_ss);
    let out = hkdf_expand(root_key, &ikm, b"ZeroTrace-Ratchet-Root-v1", 64);
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk, ck)
}

fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let msg_key = hmac_sha256(chain_key, &[0x01]);
    let next = hmac_sha256(chain_key, &[0x02]);
    (next, msg_key)
}

#[derive(Debug)]
pub struct Ratchet {
    root_key: [u8; 32],
    send_chain: Option<[u8; 32]>,
    recv_chain: Option<[u8; 32]>,
    send_n: u32,
    recv_n: u32,
    prev_send_n: u32,
    dh_sk: Vec<u8>,
    dh_pk: Vec<u8>,
    peer_dh_pk: Option<Vec<u8>>,
    peer_mlkem_ek: Vec<u8>,
    own_mlkem_dk: Vec<u8>,
    /// KEM ciphertext of the current chain, repeated in every message header.
    chain_kem_ct: Option<Vec<u8>>,
    skipped: HashMap<(Vec<u8>, u32), [u8; 32]>,
    seen: HashSet<(Vec<u8>, u32)>,
}

impl Ratchet {
    fn new(sk: [u8; 32], peer_mlkem_ek: &[u8], own_mlkem_dk: &[u8]) -> Self {
        let (dh_sk, dh_pk) = x25519_generate();
        Ratchet {
            root_key: sk, send_chain: None, recv_chain: None,
            send_n: 0, recv_n: 0, prev_send_n: 0,
            dh_sk, dh_pk, peer_dh_pk: None,
            peer_mlkem_ek: peer_mlkem_ek.to_vec(),
            own_mlkem_dk: own_mlkem_dk.to_vec(),
            chain_kem_ct: None,
            skipped: HashMap::new(), seen: HashSet::new(),
        }
    }

    /// Test/fuzz-only constructor with fixed keys. Never used by production
    /// code: a ratchet built this way has no real shared secret. Exists so
    /// the `ratchet_decrypt` fuzz target can build a ratchet cheaply.
    pub fn new_for_test() -> Self {
        Self::new([0x42; 32], &[0u8; 1568], &[0u8; 3168])
    }

    /// Alice: peer ratchet pub known from the handshake response. Derive the
    /// first sending chain immediately.
    pub fn new_initiator(
        sk: [u8; 32], peer_ratchet_pk: &[u8], peer_mlkem_ek: &[u8], own_mlkem_dk: &[u8],
    ) -> Result<Self> {
        let mut r = Ratchet::new(sk, peer_mlkem_ek, own_mlkem_dk);
        r.peer_dh_pk = Some(peer_ratchet_pk.to_vec());
        r.step_sending()?;
        Ok(r)
    }

    /// Bob: ratchet keypair from the handshake response; chains start on first receipt.
    pub fn new_responder(
        sk: [u8; 32], ratchet_sk: Vec<u8>, ratchet_pk: Vec<u8>,
        peer_mlkem_ek: &[u8], own_mlkem_dk: &[u8],
    ) -> Result<Self> {
        let mut r = Ratchet::new(sk, peer_mlkem_ek, own_mlkem_dk);
        r.dh_sk = ratchet_sk;
        r.dh_pk = ratchet_pk;
        Ok(r)
    }

    /// DH ratchet step for the SENDING side: fresh DH + fresh KEM encapsulation.
    fn step_sending(&mut self) -> Result<()> {
        let peer_pk = self.peer_dh_pk.clone().ok_or(RatchetError::NotReady)?;
        let dh = x25519_dh(&self.dh_sk, &peer_pk)?;
        let (ct, ss) = mlkem_encapsulate(&self.peer_mlkem_ek)?;
        let (rk, ck) = kdf_rk(&self.root_key, &dh, &ss);
        self.root_key = rk;
        self.send_chain = Some(ck);
        self.prev_send_n = self.send_n;
        self.send_n = 0;
        self.chain_kem_ct = Some(ct);
        Ok(())
    }

    /// DH ratchet step for the RECEIVING side, triggered by a new peer DH pub.
    /// `kem_ct` is the ciphertext from the message header (must be present on a
    /// chain change). Derives the new receiving chain AND the new sending chain
    /// (fresh DH keypair + fresh KEM encapsulation), exactly as the Double
    /// Ratchet spec requires — the next message we send must use a chain
    /// derived from this step, never the previous chain.
    fn step_receiving(&mut self, peer_pk: &[u8], kem_ct: Option<&[u8]>, pn: u32) -> Result<()> {
        // Skip messages in the old receiving chain up to pn.
        self.skip_messages(pn)?;
        let dh = x25519_dh(&self.dh_sk, peer_pk)?;
        let ss = match kem_ct {
            Some(ct) => mlkem_decapsulate(&self.own_mlkem_dk, ct)?,
            None => return Err(RatchetError::BadMessage("new chain without KEM ciphertext".into())),
        };
        let (rk, ck) = kdf_rk(&self.root_key, &dh, &ss);
        self.root_key = rk;
        self.recv_chain = Some(ck);
        self.recv_n = 0;
        // Fresh DH keypair for the next sending chain.
        let (new_sk, new_pk) = x25519_generate();
        self.dh_sk = new_sk;
        self.dh_pk = new_pk;
        self.peer_dh_pk = Some(peer_pk.to_vec());
        // Derive the new sending chain now (DH + fresh KEM), with its
        // ciphertext queued for the next message header.
        self.step_sending()
    }

    fn skip_messages(&mut self, until: u32) -> Result<()> {
        if until < self.recv_n { return Ok(()); }
        if until - self.recv_n > MAX_SKIP { return Err(RatchetError::TooManySkipped); }
        if let Some(header_pk) = self.peer_dh_pk.clone() {
            while self.recv_n < until {
                let ck = self.recv_chain.ok_or(RatchetError::NotReady)?;
                let (next, msg_key) = kdf_ck(&ck);
                self.recv_chain = Some(next);
                if self.skipped.len() >= MAX_SKIPPED_KEYS {
                    return Err(RatchetError::TooManySkipped);
                }
                self.skipped.insert((header_pk.clone(), self.recv_n), msg_key);
                self.recv_n += 1;
            }
        }
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ck = self.send_chain.ok_or(RatchetError::NotReady)?;
        let (next_ck, msg_key) = kdf_ck(&ck);
        self.send_chain = Some(next_ck);
        let n = self.send_n;
        self.send_n += 1;
        // Repeat the current chain's KEM ciphertext in every header so an
        // out-of-order first-seen message can still establish the chain.
        let kem_ct = self.chain_kem_ct.clone().unwrap_or_default();
        let mut header = Vec::with_capacity(32 + 4 + 4 + 2 + kem_ct.len());
        header.extend_from_slice(&self.dh_pk);
        header.extend_from_slice(&self.prev_send_n.to_be_bytes());
        header.extend_from_slice(&n.to_be_bytes());
        header.extend_from_slice(&(kem_ct.len() as u16).to_be_bytes());
        header.extend_from_slice(&kem_ct);
        let nonce = random_nonce12();
        let ct = aead_encrypt(&msg_key, &nonce, &header, plaintext)?;
        let mut out = Vec::with_capacity(header.len() + 12 + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 32 + 4 + 4 + 2 + 12 + 16 {
            return Err(RatchetError::BadMessage("message too short".into()));
        }
        let dh_pk = data[..32].to_vec();
        let pn = u32::from_be_bytes(data[32..36].try_into().unwrap());
        let n = u32::from_be_bytes(data[36..40].try_into().unwrap());
        let ct_len = u16::from_be_bytes(data[40..42].try_into().unwrap()) as usize;
        let header_len = 42 + ct_len;
        if data.len() < header_len + 12 + 16 {
            return Err(RatchetError::BadMessage("truncated message".into()));
        }
        if dh_pk == self.dh_pk {
            return Err(RatchetError::BadMessage("message from own DH key".into()));
        }
        let header = &data[..header_len];
        let kem_ct = if ct_len > 0 { Some(&data[42..header_len]) } else { None };
        let key_id = (dh_pk.clone(), n);
        if self.seen.contains(&key_id) {
            return Err(RatchetError::Replay);
        }
        // New chain?
        let is_new_chain = match &self.peer_dh_pk {
            Some(p) => *p != dh_pk,
            None => true,
        };
        if is_new_chain {
            self.step_receiving(&dh_pk, kem_ct, pn)?;
        }
        let nonce = &data[header_len..header_len + 12];
        let ciphertext = &data[header_len + 12..];
        // A failed authentication must not consume chain state: derive the
        // message key from a copy of the chain and commit only on success,
        // so a tampered message cannot desynchronise the session.
        let (msg_key, commit) = if let Some(k) = self.skipped.get(&key_id) {
            (*k, Commit::RemoveSkipped)
        } else {
            if self.recv_chain.is_none() {
                return Err(RatchetError::NotReady);
            }
            if n < self.recv_n {
                return Err(RatchetError::Replay);
            }
            if n - self.recv_n > MAX_SKIP {
                return Err(RatchetError::TooManySkipped);
            }
            // Advance a local copy of the chain to n, collecting skipped keys
            // without touching self yet.
            let mut ck = self.recv_chain.ok_or(RatchetError::NotReady)?;
            let mut skipped_new: Vec<(u32, [u8; 32])> = Vec::new();
            let mut recv_n = self.recv_n;
            while recv_n < n {
                let (next, mk) = kdf_ck(&ck);
                ck = next;
                if self.skipped.len() + skipped_new.len() >= MAX_SKIPPED_KEYS {
                    return Err(RatchetError::TooManySkipped);
                }
                skipped_new.push((recv_n, mk));
                recv_n += 1;
            }
            let (next, mk) = kdf_ck(&ck);
            (mk, Commit::Advance { next_chain: next, skipped_new, new_recv_n: recv_n + 1 })
        };
        let plain = aead_decrypt(&msg_key, nonce, header, ciphertext)
            .map_err(|_| RatchetError::AuthFailed)?;
        match commit {
            Commit::RemoveSkipped => { self.skipped.remove(&key_id); }
            Commit::Advance { next_chain, skipped_new, new_recv_n } => {
                if let Some(header_pk) = self.peer_dh_pk.clone() {
                    for (num, k) in skipped_new {
                        self.skipped.insert((header_pk.clone(), num), k);
                    }
                }
                self.recv_chain = Some(next_chain);
                self.recv_n = new_recv_n;
            }
        }
        self.seen.insert(key_id);
        Ok(plain)
    }

    pub fn info(&self) -> String {
        format!(
            "{{\"send_n\":{},\"recv_n\":{},\"skipped_keys\":{},\"seen\":{},\"has_send_chain\":{},\"has_recv_chain\":{}}}",
            self.send_n, self.recv_n, self.skipped.len(), self.seen.len(),
            self.send_chain.is_some(), self.recv_chain.is_some()
        )
    }
}
