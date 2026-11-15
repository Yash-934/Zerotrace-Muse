# Security — ZeroTrace Messenger

## Reporting a vulnerability

This is experimental software with unaudited components. If you find a
vulnerability:

- **Do not open a public issue.**
- Contact the author privately with: what you found, how to reproduce it,
  and what you think the impact is.
- Do not test against other people's devices or sessions.

There is no bug-bounty programme. Reports are handled on a best-effort basis.

## What is in place

- Post-quantum + classical hybrid crypto (ML-KEM-1024, ML-DSA-87,
  X25519, Ed25519) — see `docs/CRYPTOGRAPHIC_PROTOCOL.md`.
- Authenticated QR pairing with fingerprint verification; no silent
  identity replacement.
- Tor-only transport, fail-closed; no clearnet fallback.
- Hardware-backed Keystore wrapping (actual level reported).
- RAM-only messages; single destruction path on lock/disconnect/timeout.
- `FLAG_SECURE`, no backups, no notification content, minimal permissions.
- Rust core: 10 protocol/crypto tests, all passing; fuzzing skeleton in
  `rust-core/fuzz/` (not yet run).

## What is NOT in place

- No independent security audit (code, crypto, or build).
- No fuzzing run has been executed yet.
- No two-device live-Tor test has been executed yet.
- The PQXDH-Sync v1 handshake has no independent review.
- ML-KEM / ML-DSA crates are unaudited at the versions used.
- No verified supply-chain story beyond version pinning (no lockfile
  review, no reproducible-build check).

See `docs/LIMITATIONS.md` for the full list.
