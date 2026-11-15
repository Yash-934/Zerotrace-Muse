//! Fuzz the QR commitment parser: arbitrary strings must never panic, only
//! return Ok (valid commitment) or Err (rejected). Run with `cargo fuzz`.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Any timestamp is fine for fuzzing; the parser only checks expiry.
        let _ = zerotrace_core::identity::verify_pairing_qr(s, 1_800_000_000);
    }
});
