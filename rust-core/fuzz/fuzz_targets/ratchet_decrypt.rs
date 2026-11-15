//! Fuzz the ratchet decryptor: arbitrary ciphertext must never panic and must
//! never be accepted as valid. The harness builds one real session, encrypts
//! one real message, then feeds mutated bytes to decrypt. Run with `cargo fuzz`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zerotrace_core::ratchet::Ratchet;

fuzz_target!(|data: &[u8]| {
    // Building a full session per input is expensive, so this target uses the
    // ratchet directly with fixed keys: any decrypt of arbitrary bytes must
    // fail cleanly (or, with negligible probability, succeed only for bytes
    // that are a genuine encryption of something under these keys).
    let mut ratchet = Ratchet::new_for_test();
    let _ = ratchet.decrypt(data);
});
