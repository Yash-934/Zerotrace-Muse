//! Per-call media transport: RTP framing + ChaCha20-Poly1305 payload encryption.
//!
//! No new crypto primitive is introduced here. The AEAD is the one already in
//! `crypto.rs` (ChaCha20-Poly1305, reviewed crate). The construction is:
//!
//! * one fresh 32-byte media key per call (OsRng), exchanged inside the
//!   ratchet-encrypted invite — see `docs/CALLING_PHASE1.md` §4;
//! * one standard RTP packet (RFC 3550) per 20 ms Opus frame: 12-byte header
//!   (V=2, PT=96 dynamic/Opus, per-direction sequence, 48 kHz timestamp,
//!   per-direction SSRC) + AEAD ciphertext of the Opus payload;
//! * nonce (12 B): `[direction:1][SSRC:4][seq:2][timestamp:4][0x00:1]` —
//!   unique per key per packet by construction (SSRC differs per direction,
//!   sequence increments). Direction bytes: caller->callee 0xA1,
//!   callee->caller 0xB2, so a reflected frame can never decrypt as the
//!   other direction's frame;
//! * AAD: `callId || "zt-call-media-v1" || RTP header` — binds the header
//!   (sequence/timestamp/SSRC) to the ciphertext;
//! * replay protection: per-direction highest sequence + 64-bit window
//!   (SRTP-style). Duplicates and old packets are dropped, never delivered.
//!
//! This is NOT SRTP. It reuses a reviewed AEAD with unique nonces, AAD
//! binding and a replay window, but the construction as a whole has no
//! independent review. See `docs/CALLING_PHASE1.md` §8 and the Phase 4
//! audit requirement. Keys are zeroed on call end (`zeroize`).
use crate::crypto::{aead_decrypt, aead_encrypt, random_bytes, CryptoError, Result};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CALL_ID_LEN: usize = 16;
pub const MEDIA_KEY_LEN: usize = 32;
pub const RTP_PT_OPUS: u8 = 96;
pub const RTP_HEADER_LEN: usize = 12;
/// Max Opus plaintext per frame: 20 ms at 24 kbit/s is ~60 bytes; 2048 is a
/// generous hard cap so a corrupt or hostile frame cannot allocate wildly.
pub const MAX_OPUS_FRAME: usize = 2048;
const AAD_LABEL: &[u8] = b"zt-call-media-v1";
const DIR_CALLER: u8 = 0xA1;
const DIR_CALLEE: u8 = 0xB2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaDirection {
    CallerToCallee,
    CalleeToCaller,
}

impl MediaDirection {
    fn byte(self) -> u8 {
        match self {
            MediaDirection::CallerToCallee => DIR_CALLER,
            MediaDirection::CalleeToCaller => DIR_CALLEE,
        }
    }
}

/// One side's send state and the other side's receive state, for one call.
/// `is_caller` is the LOCAL device's role: it decides which direction byte
/// our sends carry and which direction byte our receives must carry.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Call {
    #[zeroize(skip)]
    pub call_id: [u8; CALL_ID_LEN],
    key: [u8; MEDIA_KEY_LEN],
    #[zeroize(skip)]
    pub is_caller: bool,
    send_seq: u16,
    send_ts: u32,
    send_ssrc: u32,
    recv_ssrc: Option<u32>,
    recv_highest: u16,
    recv_window: u64,
    /// Set once the onion stream for this call is established (either side).
    #[zeroize(skip)]
    pub connected: bool,
}

impl Call {
    pub fn new(call_id: [u8; CALL_ID_LEN], key: [u8; MEDIA_KEY_LEN], is_caller: bool) -> Self {
        let mut seed = [0u8; 10];
        seed.copy_from_slice(&random_bytes(10));
        let send_seq = u16::from_be_bytes([seed[0], seed[1]]);
        let send_ts = u32::from_be_bytes([seed[2], seed[3], seed[4], seed[5]]);
        let send_ssrc = u32::from_be_bytes([seed[6], seed[7], seed[8], seed[9]]);
        Call {
            call_id,
            key,
            is_caller,
            send_seq,
            send_ts,
            send_ssrc,
            recv_ssrc: None,
            recv_highest: 0,
            recv_window: 0,
            connected: false,
        }
    }

    fn send_dir(&self) -> MediaDirection {
        if self.is_caller {
            MediaDirection::CallerToCallee
        } else {
            MediaDirection::CalleeToCaller
        }
    }

    fn recv_dir(&self) -> MediaDirection {
        if self.is_caller {
            MediaDirection::CalleeToCaller
        } else {
            MediaDirection::CallerToCallee
        }
    }

    fn rtp_header(&self, seq: u16, ts: u32) -> [u8; RTP_HEADER_LEN] {
        let mut h = [0u8; RTP_HEADER_LEN];
        h[0] = 0x80; // V=2, P=0, X=0, CC=0
        h[1] = RTP_PT_OPUS; // M=0, PT=96
        h[2..4].copy_from_slice(&seq.to_be_bytes());
        h[4..8].copy_from_slice(&ts.to_be_bytes());
        h[8..12].copy_from_slice(&self.send_ssrc.to_be_bytes());
        h
    }

    fn nonce(&self, dir: MediaDirection, header: &[u8; RTP_HEADER_LEN]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = dir.byte();
        n[1..5].copy_from_slice(&header[8..12]); // SSRC
        n[5..7].copy_from_slice(&header[2..4]); // seq
        n[7..11].copy_from_slice(&header[4..8]); // timestamp
        n
    }

    fn aad(&self, header: &[u8; RTP_HEADER_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(CALL_ID_LEN + AAD_LABEL.len() + RTP_HEADER_LEN);
        aad.extend_from_slice(&self.call_id);
        aad.extend_from_slice(AAD_LABEL);
        aad.extend_from_slice(header);
        aad
    }

    /// Encrypt one 20 ms Opus frame into a complete RTP packet.
    pub fn encode_audio(&mut self, opus: &[u8]) -> Result<Vec<u8>> {
        if opus.is_empty() || opus.len() > MAX_OPUS_FRAME {
            return Err(CryptoError::BadLength("opus frame", opus.len()));
        }
        let seq = self.send_seq;
        let ts = self.send_ts;
        let header = self.rtp_header(seq, ts);
        let dir = self.send_dir();
        let nonce = self.nonce(dir, &header);
        let aad = self.aad(&header);
        let ct = aead_encrypt(&self.key, &nonce, &aad, opus)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.send_ts = self.send_ts.wrapping_add(960); // 20 ms at 48 kHz
        let mut out = Vec::with_capacity(RTP_HEADER_LEN + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Replay check (SRTP-style window). Returns Ok(true) if the sequence is
    /// fresh, Ok(false) if it is a duplicate/old packet.
    fn replay_fresh(&mut self, seq: u16) -> bool {
        if self.recv_ssrc.is_none() {
            return true; // first packet binds the SSRC below; seq is fresh
        }
        let diff = seq.wrapping_sub(self.recv_highest) as i16;
        if diff > 0 {
            // New highest: shift the window.
            let shift = diff as u64;
            self.recv_window = if shift >= 64 { 0 } else { self.recv_window << shift };
            self.recv_window |= 1;
            self.recv_highest = seq;
            true
        } else if diff == 0 {
            false // duplicate of the highest
        } else {
            let back = (-diff) as u64;
            if back >= 64 {
                return false; // too old
            }
            let bit = 1u64 << back;
            if self.recv_window & bit != 0 {
                return false; // already seen
            }
            self.recv_window |= bit;
            true
        }
    }

    /// Authenticate + decrypt one RTP packet. Returns the Opus bytes, or an
    /// error (auth failure, replay, malformed header, SSRC mismatch).
    ///
    /// Ordering matters: authentication runs FIRST, using only the packet's
    /// own header bytes (the nonce is derived from them). No receive state
    /// (SSRC binding, replay window) changes until the packet has opened —
    /// a forged packet can neither bind a wrong SSRC nor burn sequence
    /// numbers.
    pub fn decode_audio(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < RTP_HEADER_LEN + 16 {
            return Err(CryptoError::BadLength("rtp packet", packet.len()));
        }
        let header: [u8; RTP_HEADER_LEN] = packet[..RTP_HEADER_LEN].try_into().unwrap();
        if header[0] != 0x80 || header[1] != RTP_PT_OPUS {
            return Err(CryptoError::Failed("bad rtp header".to_string()));
        }
        let seq = u16::from_be_bytes([header[2], header[3]]);
        let ssrc = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        // Authenticate first, from the header bytes alone.
        let dir = self.recv_dir();
        let nonce = self.nonce(dir, &header);
        let aad = self.aad(&header);
        let plain = aead_decrypt(&self.key, &nonce, &aad, &packet[RTP_HEADER_LEN..])?;
        if plain.len() > MAX_OPUS_FRAME {
            return Err(CryptoError::BadLength("opus frame", plain.len()));
        }
        match self.recv_ssrc {
            None => {
                self.recv_ssrc = Some(ssrc);
                self.recv_highest = seq.wrapping_sub(1);
                self.recv_window = 0;
            }
            Some(bound) if bound != ssrc => {
                return Err(CryptoError::Failed("ssrc mismatch".to_string()));
            }
            _ => {}
        }
        if !self.replay_fresh(seq) {
            return Err(CryptoError::Failed("replayed media packet".to_string()));
        }
        Ok(plain)
    }
}

/// Registry of live calls. Keys live here and are zeroed when the call ends
/// (Call implements ZeroizeOnDrop; removing it from the map drops it).
pub struct CallRegistry {
    calls: HashMap<[u8; CALL_ID_LEN], Call>,
}

impl CallRegistry {
    pub fn new() -> Self {
        CallRegistry { calls: HashMap::new() }
    }

    /// Caller side: fresh callId + media key, registered as caller.
    pub fn begin(&mut self) -> ([u8; CALL_ID_LEN], [u8; MEDIA_KEY_LEN]) {
        let id = random_bytes(CALL_ID_LEN);
        let key = random_bytes(MEDIA_KEY_LEN);
        let mut call_id = [0u8; CALL_ID_LEN];
        let mut media_key = [0u8; MEDIA_KEY_LEN];
        call_id.copy_from_slice(&id);
        media_key.copy_from_slice(&key);
        self.calls.insert(call_id, Call::new(call_id, media_key, true));
        (call_id, media_key)
    }

    /// Callee side: register a call the peer invited us to.
    pub fn join(&mut self, call_id: [u8; CALL_ID_LEN], key: [u8; MEDIA_KEY_LEN]) -> bool {
        if self.calls.contains_key(&call_id) {
            return false;
        }
        self.calls.insert(call_id, Call::new(call_id, key, false));
        true
    }

    pub fn end(&mut self, call_id: &[u8; CALL_ID_LEN]) {
        self.calls.remove(call_id); // Drop zeroizes the key.
    }

    pub fn contains(&self, call_id: &[u8; CALL_ID_LEN]) -> bool {
        self.calls.contains_key(call_id)
    }

    pub fn set_connected(&mut self, call_id: &[u8; CALL_ID_LEN], connected: bool) {
        if let Some(c) = self.calls.get_mut(call_id) {
            c.connected = connected;
        }
    }

    pub fn is_connected(&self, call_id: &[u8; CALL_ID_LEN]) -> bool {
        self.calls.get(call_id).map(|c| c.connected).unwrap_or(false)
    }

    pub fn encode_audio(&mut self, call_id: &[u8; CALL_ID_LEN], opus: &[u8]) -> Result<Vec<u8>> {
        match self.calls.get_mut(call_id) {
            Some(c) => c.encode_audio(opus),
            None => Err(CryptoError::Failed("unknown call".to_string())),
        }
    }

    pub fn decode_audio(&mut self, call_id: &[u8; CALL_ID_LEN], packet: &[u8]) -> Result<Vec<u8>> {
        match self.calls.get_mut(call_id) {
            Some(c) => c.decode_audio(packet),
            None => Err(CryptoError::Failed("unknown call".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Call, Call) {
        let id = [7u8; CALL_ID_LEN];
        let key = [9u8; MEDIA_KEY_LEN];
        (Call::new(id, key, true), Call::new(id, key, false))
    }

    #[test]
    fn media_roundtrip_both_directions() {
        let (mut caller, mut callee) = pair();
        let opus = vec![0x11u8; 60];
        let pkt = caller.encode_audio(&opus).unwrap();
        assert_eq!(callee.decode_audio(&pkt).unwrap(), opus);
        // And back.
        let pkt2 = callee.encode_audio(&opus).unwrap();
        assert_eq!(caller.decode_audio(&pkt2).unwrap(), opus);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (mut caller, mut callee) = pair();
        let mut pkt = caller.encode_audio(&[0x22u8; 40]).unwrap();
        let last = pkt.len() - 1;
        pkt[last] ^= 0x01;
        assert!(callee.decode_audio(&pkt).is_err());
    }

    #[test]
    fn tampered_header_rejected() {
        let (mut caller, mut callee) = pair();
        let mut pkt = caller.encode_audio(&[0x22u8; 40]).unwrap();
        pkt[3] ^= 0x01; // sequence byte
        assert!(callee.decode_audio(&pkt).is_err());
    }

    #[test]
    fn replay_rejected() {
        let (mut caller, mut callee) = pair();
        let pkt = caller.encode_audio(&[0x33u8; 40]).unwrap();
        assert!(callee.decode_audio(&pkt).is_ok());
        assert!(callee.decode_audio(&pkt).is_err()); // same packet again
    }

    #[test]
    fn reflected_frame_rejected() {
        // A caller->callee packet must not decrypt as callee->caller.
        let (mut caller, mut callee) = pair();
        let pkt = caller.encode_audio(&[0x44u8; 40]).unwrap();
        assert!(caller.decode_audio(&pkt).is_err());
        let _ = &mut callee;
    }

    #[test]
    fn out_of_order_within_window_ok() {
        let (mut caller, mut callee) = pair();
        let p1 = caller.encode_audio(&[1u8; 20]).unwrap();
        let p2 = caller.encode_audio(&[2u8; 20]).unwrap();
        let p3 = caller.encode_audio(&[3u8; 20]).unwrap();
        // Deliver 1, 3, then 2 (late but inside the window).
        assert_eq!(callee.decode_audio(&p1).unwrap(), vec![1u8; 20]);
        assert_eq!(callee.decode_audio(&p3).unwrap(), vec![3u8; 20]);
        assert_eq!(callee.decode_audio(&p2).unwrap(), vec![2u8; 20]);
    }

    #[test]
    fn wrong_call_key_rejected() {
        let (mut caller, mut callee) = pair();
        let mut other = Call::new([8u8; CALL_ID_LEN], [10u8; MEDIA_KEY_LEN], false);
        let pkt = caller.encode_audio(&[0x55u8; 40]).unwrap();
        assert!(other.decode_audio(&pkt).is_err());
        let _ = &mut callee;
    }

    #[test]
    fn oversize_opus_frame_rejected() {
        let (mut caller, _) = pair();
        assert!(caller.encode_audio(&vec![0u8; MAX_OPUS_FRAME + 1]).is_err());
    }
}
