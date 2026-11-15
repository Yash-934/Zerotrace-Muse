//! Fuzz the handshake responder: arbitrary Init bytes must never panic, only
//! return Ok (response) or Err (rejected). Run with `cargo fuzz`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zerotrace_core::handshake::responder_respond;
use zerotrace_core::identity::Identity;

fuzz_target!(|data: &[u8]| {
    // A fixed responder identity: the fuzzer varies only the Init bytes.
    let responder = Identity::generate();
    let peer = responder.public();
    let _ = responder_respond(&responder, &peer, data);
});
