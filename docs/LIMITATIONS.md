# Limitations — ZeroTrace Messenger v0.3.0-experimental

Read this before using the app or describing it to anyone. Every item here
is a real limitation of this build, not a roadmap tease.

## Security limitations

1. **PQXDH-Sync v1 is unreviewed.** The handshake is a new serverless
   adaptation of Signal PQXDH. No independent cryptographer has reviewed it.
   It must not be described as "Signal-grade" or "proven".
2. **ML-KEM and ML-DSA crates are unaudited** at the versions used.
3. **No ML-KEM Braid / SPQR.** The ratchet folds a fresh ML-KEM
   encapsulation into every DH step (DH+KEM), but there is no incremental
   KEM ratcheting. See `docs/CRYPTOGRAPHIC_PROTOCOL.md` §5.
4. **No one-time prekey.** A compromised signed prekey is more valuable to
   an attacker than in Signal's design. Inherent to having no server.
5. **No independent audit of the app at all** — code, build, or deployment.
6. **Tor integration is untested on the live network.** The Arti runtime
   compiles and its state machine runs, but no two-device message has yet
   crossed the real Tor network in testing. Onion-service reachability,
   bootstrap time and circuit reliability on real phones are unverified.
7. **The responder's ratchet messages use a fresh outgoing connection**
   (extra Tor circuit per session) because the accepted stream's write half
   is not retained in v0.1.
8. **No forward secrecy for the identity itself.** If the identity keys are
   ever extracted, past handshakes that used them can be re-derived up to
   the ratchet's forward secrecy. This is true of Signal too; it is stated
   here so nobody claims otherwise.
9. **RAM-only is best effort.** The OS may page memory, and a live forensic
   acquisition can read RAM. NAND erasure is not guaranteed.

## Product limitations (v0.3.0)

- One-to-one messaging: text, emoji, replies, reactions, images, files
  (10 MB cap), voice notes, live-only status, **voice calls (experimental)**.
  **No video calls, no groups, no persistent history.**
- **Voice calls are experimental (v0.3.0, Phase 1).** Tor-native transport:
  Opus audio over the onion service with a fresh per-call media key. Expect
  noticeable latency and occasional audio gaps — Tor rendezvous + 3-hop
  circuits + TCP retransmissions are slow. No live-Tor call test has run
  yet in this environment.
- **Video calls are not implemented.** Voice only in v0.3.0.
- **The call endpoint is the identity onion address in Phase 1** (not a
  fresh per-call onion service). Arti 0.48 cannot create RAM-only service
  keys (see `docs/CALLING_PHASE1.md` §1–2: TODO #1186, #1106, disk keystore
  by default). The peer already knows this address; media content stays
  protected by the fresh per-call key.
- **Media encryption is ChaCha20-Poly1305 over RTP payloads, NOT SRTP.**
  It reuses a reviewed AEAD with unique nonces, AAD binding and a replay
  window, but the construction as a whole has no independent review.
- **Opus is device-dependent.** Some devices lack an Opus encoder/decoder;
  the call then fails honestly at start with a clear message.
- **Groups are planned, not built.** They need a reviewed group E2EE
  protocol (e.g. MLS); reusing the 1:1 ratchet would be incorrect.
- **Status is live-only.** A status is visible only while a live session
  exists with that peer; it is never stored or relayed, and there is no
  24-hour availability. Status audience selection is not yet exposed in the
  UI — a status goes to all live session peers.
- **File metadata is visible to the peer**: file name, size, MIME type and
  SHA-256 hash (needed for the transfer). Avoid sensitive file names.
- **Delivery/read receipts are metadata**: the peer learns when a message
  was delivered and read. This is inherent to the feature.
- Both peers must be online simultaneously. No offline queue, no
  store-and-forward.
- Session timeout default 10 minutes (configurable 1–60). A timed-out
  session must be re-established from scratch (bundle exchange + handshake).
- Tor bootstrap on first run can take 1–3 minutes; on a network that blocks
  Tor, messaging is unavailable with no workaround by design.
- QR pairing requires the two people to meet (or use an already-trusted
  channel) to compare fingerprints. There is no in-app contact discovery.
- Chat history is lost on disconnect, lock, timeout, process death, or
  reboot. That is the point — but it also means no message recovery.
- The app has not been run on a physical device in this environment. The
  Kotlin code is compile-verified and the Rust core is test-verified, but
  first-run behaviour on a real phone (Keystore levels, camera, Tor
  bootstrap) is unverified.
- UI text is English-only in v2 (localisation debt from v1; the Hindi
  strings file exists but the UI does not use string resources yet).
- The Rust `.so` is **not** built by the Gradle build in this repo yet: the
  user must build it with `cargo ndk` and place it in
  `app/src/main/jniLibs/<abi>/` (see README). Until that is done, the app
  starts but the Rust core reports unavailable and messaging is disabled.

## Honesty rules (from the brief, kept)

- Never claim quantum-proof, Pegasus-proof, Cellebrite-proof, or completely
  untraceable.
- The Security Dashboard shows only real status; nothing is green for an
  unimplemented feature.
- Experimental components stay visibly labelled EXPERIMENTAL in the UI.
