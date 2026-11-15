# Fuzzing — ZeroTrace Rust core

Skeleton only. **These targets have not been run yet** — they are provided so
the next step (an actual fuzzing run) needs no new scaffolding.

## Targets

| Target | What it fuzzes |
|---|---|
| `qr_parse` | `identity::verify_pairing_qr` — arbitrary strings must never panic |
| `handshake_init` | `handshake::responder_respond` — arbitrary Init bytes must never panic |
| `ratchet_decrypt` | `ratchet::decrypt` — arbitrary ciphertext must never panic / never be accepted |

## Running

```bash
cd rust-core
cargo install cargo-fuzz        # needs a nightly toolchain for libFuzzer
cargo fuzz run qr_parse -- -max_total_time=600
cargo fuzz run handshake_init -- -max_total_time=600
cargo fuzz run ratchet_decrypt -- -max_total_time=600
```

## Notes

- `ratchet_decrypt` uses `Ratchet::new_for_test()` — a test-only constructor
  with fixed keys. It exists for this harness; it is not used by production
  code paths. (If it does not exist yet, add it to `ratchet.rs` as a
  `#[cfg(test)]`-adjacent test helper before running the target.)
- The Kotlin QR parser (`PairingFormat`) has JVM unit tests instead
  (`app/src/test/.../PairingFormatTest.kt`, 12 cases); the equivalent
  Kotlin-side fuzzing is not set up.
