//! Best-effort secret handling: short-lived buffers, explicit zeroing.
use zeroize::Zeroize;

/// A byte buffer that zeroes itself on drop.
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

pub fn zero(buf: &mut [u8]) {
    buf.zeroize();
}
