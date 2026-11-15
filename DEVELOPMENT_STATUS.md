# Development Status — ZeroTrace Messenger v0.3.0-experimental

Last updated: 2026-11-15. This file is the honest record: what is done, what
is verified, and what is not. Nothing here claims a test that did not run.

## v0.3.0 — Tor-native voice calls, Phase 1 (2026-11-15)

The user's own research concluded that Tor-native TCP calling is workable
(no UDP/direct IP needed — ICE-TCP and TURN-over-TCP are standardized, but
the right answer for ZeroTrace is an onion-service media transport, not
TURN). Implemented as designed in `docs/CALLING_PHASE1.md`.

| v0.3.0 work | Status | Evidence |
|---|---|---|
| Arti 0.48 audit (vendored sources) | ✅ Done | Multiple onion services possible, but RAM-only service keys are NOT (TODO #1186, #1106; disk keystore default; `launch_onion_service_with_hsid` behind `experimental-api`) |
| Design doc | ✅ Done | `docs/CALLING_PHASE1.md` incl. the one deviation: Phase 1 uses the identity onion service + one-time callId + fresh media key |
| Rust media transport (`call.rs`) | ✅ Done | RTP + ChaCha20-Poly1305 payload AEAD, nonce/AAD binding, replay window; 8 unit tests |
| Rust call queues + Arti stream binding (`tor.rs`) | ✅ Done | `cargo check --features tor` clean |
| JNI surface (call begin/join/end/connect/send/poll/event) | ✅ Done | `ffi.rs` + `RustCoreBridge.kt` in sync |
| Kotlin signaling (WireFrame 0x0B–0x0E) | ✅ Done | 4 new unit tests |
| Audio engine (Opus via MediaCodec, AEC/NS, jitter buffer) | ✅ Done | Runtime Opus capability check; no silent fallback |
| ViewModel call state machine + real CallScreen | ✅ Done | Outgoing/Incoming/Connecting/InCall/Ended — all real |
| Verification + v3 zip | ✅ Done | Full manual build green (`compiled`, D8 + zipalign + debug sign OK, 70.0 MB verification APK in work dir only — NOT shipped); cargo 18/18; Kotlin 38/38; zip `ZeroTraceMessenger-Project-v3.zip` (126 files, 252 KB, code-only) delivered 2026-11-15 |

One deliberate deviation from the user's proposal, documented in the design
doc §1–2: Phase 1 does NOT create a per-call onion service, because Arti
0.48 would persist each call's service key to disk. Per-call ephemeral
services are Phase 1.1, blocked on Arti keystore work.

## v0.2.0 — WhatsApp-style UX upgrade (2026-11-15)

Audit first (`docs/ARCHITECTURE_MAP_v2.md`), then a full UI upgrade on the
existing codebase — no rewrite, no crypto change, no new network dependency.
Security review: `docs/UX_UPGRADE_v2.md`.

| v2 phase | Status | Evidence |
|---|---|---|
| 1 — Audit + architecture map + baseline | ✅ Done | `docs/ARCHITECTURE_MAP_v2.md`; cargo 10/10 baseline |
| 2 — Design system (components, light/dark theme, accents) | ✅ Done | `ui/components/Components.kt`, `ui/theme/Theme.kt` |
| 3 — Navigation + screens (Chats/Updates/Calls/Settings, chat, profile, call, settings) | ✅ Done | `ui/MainTabs.kt`, `ui/ChatScreen.kt`, `ui/ContactProfileScreen.kt`, `ui/CallScreen.kt`, `ui/SettingsScreen.kt`, `ui/Onboarding.kt`, `ui/CameraScreen.kt` |
| 4 — Real wiring (per-contact sessions, file framing, live-only status, real acks) | ✅ Done | `session/ZeroTraceViewModel.kt` (rewritten), `session/FileProtocol.kt`, `session/ConversationState.kt`; Kotlin tests 34/34 |
| 5 — Security review + docs | ✅ Done | `docs/UX_UPGRADE_v2.md`, `docs/LIMITATIONS.md`, `README.md` |
| 6 — Verification + v2 zip | ✅ Done | Full manual build green (`compiled`, D8 + zipalign + debug sign OK, 69.8 MB verification APK in work dir only — NOT shipped); Kotlin tests 34/34; cargo 10/10; zip `ZeroTraceMessenger-Project-v2.zip` (155 files, 2.9 MB, code-only) delivered 2026-11-15 |

New in v2 (all real, none faked): per-contact live sessions (one Rust
session per contact, each with its own receive loop/timeout); WhatsApp-style
tabs and chat list (search, unread, mute, pin); replies, reactions, real
delivery/read receipts (encrypted acks); file sharing chunked over the
ratchet (16 KiB chunks, 10 MB cap, SHA-256 verified, offer/accept, no
auto-save, no temp files); voice notes (MediaRecorder → pipe fd → RAM);
in-app camera (ImageCapture → JPEG bytes in RAM); live-only status; contact
block/remove/rename; device-PIN app lock; clipboard auto-clear (30 s);
light/dark/system theme + accent choice. Calls and groups are honestly
unavailable (Tor is TCP-only; groups need a reviewed group protocol) —
see `docs/UX_UPGRADE_v2.md` §2.

One real bug fixed during v2: `openSession` used to accept ANY non-JSON
bundle frame as the handshake response; a peer's Init frame arriving
mid-handshake could have been mistaken for it. v2 accepts only a 64-byte
frame as the response (verified against `handshake.rs`: response = 32-byte
ratchet key + 32-byte confirmation; Init is 1600+ bytes starting 0x01).

New dependency (only one): `androidx.compose.material:material-icons-extended`
1.7.0 (UI icons; no network, no telemetry). Manual-pipeline note:
`build_zerotrace.py compile` reuses the cached AAR extraction — after adding
a dependency, run `build_zerotrace.py all` (or `extract`) once, otherwise the
new artifact is silently missing from the classpath.

## Phase status (v0.1.0, carried over)

| Phase | Status | Evidence |
|---|---|---|
| 0 — Feasibility, threat model, architecture | ✅ Done | `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, this file |
| 1 — Android foundation (Gradle, Compose UI, Keystore) | ✅ Done | Kotlin compile-verified, 71 classes (see below) |
| 2 — Rust security core (identity, crypto, ratchet, JNI) | ✅ Done | `cargo test` 10/10 (see below) |
| 3 — QR pairing (commitment format, verification) | ✅ Done | Kotlin unit tests 12/12; Rust QR tests in the 10 |
| 4 — PQ session (PQXDH-Sync handshake + Double Ratchet) | ✅ Done | `cargo test` 6/6 protocol tests (see below) |
| 5 — Tor networking (Arti, onion service, fail-closed) | ⚠️ Implemented, **not live-tested** | `cargo check --features tor` clean; no live-Tor test yet |
| 6 — Real chat wiring (UI ↔ Rust ↔ Tor, RAM-only, timeout) | ⚠️ Implemented, **not end-to-end tested** | Code complete; no two-device test yet |
| 7 — Android hardening (FLAG_SECURE, backup, notifications) | ✅ Done | In code; compile-verified |
| 8 — Release readiness (verify, docs, deliver code-only zip) | ✅ Done (v0.1.0) | Docs complete; v0.1.0 zip `ZeroTraceMessenger-Project-v1.zip` delivered 2026-11-15; superseded by v0.2.0 below |

## Test evidence (actually run, 2026-11-15)

### Rust — `cargo test` (default features): 18/18 pass
- 4 crypto tests: ML-KEM-1024 sizes/roundtrip/wrong-key, ML-DSA-87
  sizes/sign/verify/tamper, X25519/Ed25519/AEAD, HKDF determinism.
- 6 protocol tests: full handshake bidirectional, tampered Init rejected,
  identity mismatch rejected, replay+tamper rejected, out-of-order delivery,
  QR commitment roundtrip + full-bundle verification + swapped-PQ-key rejection.
- 8 call media tests (new, v0.3.0): RTP roundtrip both directions, tampered
  payload rejected, tampered header rejected, replay rejected, reflected
  frame rejected (direction byte), out-of-order within window accepted,
  wrong call key rejected, oversize Opus frame rejected.
- `cargo check --features tor`: clean, 0 errors, 0 warnings (arti-client is
  actually used now — the earlier "unused dependency" warning is gone).
- The in-process self-test (`nativeSelfTest`, shown on the dashboard) now
  also runs a one-call media roundtrip + replay check.

### Kotlin unit tests — 38/38 pass (JVM, JUnit 4)
- `PairingFormatTest`: 12 cases (valid parse, fingerprint determinism and
  grouping, onion sensitivity, non-JSON, wrong protocol/version, expired,
  far-future expiry, bad onion, short/non-hex key, missing capability,
  oversized, missing signature).
- `TorStateTest`: 10 cases (11 states exist, only `E2EE_SESSION_READY` is
  ready, fail-closed `canSend` rule, every state has a user label).
- `FileProtocolTest` (v2): 12 cases (text frame roundtrip with msg id,
  legacy bare-UTF-8 accepted as text, malformed frames dropped, oversize
  offer rejected, file offer/chunk/done roundtrip with integrity, tampered
  bytes fail integrity, duplicate/out-of-range/oversize chunks rejected,
  ack/reaction/file-response roundtrip, status roundtrip, MIME allowlist,
  file-name sanitisation, SHA-256 determinism).
- `FileProtocolTest` call signaling (new, v0.3.0): 4 cases (invite
  roundtrip with callId hex + 32-byte key, accept/decline/end roundtrip,
  malformed call frames dropped — bad id, short key, non-hex id — callId
  hex validation).
- Note: JVM runs need the real `org.json` jar — `android.jar`'s org.json is
  a stub that throws. `testImplementation("org.json:json:20240303")` covers
  this in Gradle.

### Kotlin compile — manual pipeline (kotlinc + aapt2, no Gradle), v0.2.0
- aapt2 link: OK (v2 resources incl. new screens).
- kotlinc: OK — **301 compiled class files** (v0.2.0 was 270, v0.1.0 was 71;
  the growth is the new screens + component library + call engine — each
  @Composable generates several classes). Top-level classes include ConversationState, FileProtocol,
  Components, MainTabs, ChatScreen, ContactProfileScreen, CallScreen,
  SettingsScreen, Onboarding, CameraScreen, VoiceRecorder.
- D8 + zipalign + debug sign: OK, 69.8 MB verification APK (work dir only —
  the APK is NOT a deliverable and is NOT shipped; see the APK rule below).
- Gradle build has **not** been run in this environment (no Gradle CLI
  here); the user builds with Gradle in Antigravity IDE.

## Real bugs found by tests (and fixed)

1. **Ratchet `step_receiving` did not derive the new sending chain**
   (spec-correctness bug) — fixed, covered by the handshake tests.
2. **Decrypt consumed chain state on AEAD failure** — a failed decrypt must
   not advance the ratchet. Fixed with a commit-on-success design; covered
   by the replay/tamper tests.
3. **Keystore `getKeySpec` is not generic on Android** — `SecretKeyFactory`
   returns `KeySpec`, not `KeyInfo`; a cast is required. Found by the
   kotlinc compile.
4. **Compose plugin needs the embeddable compiler** — the standalone
   `kotlin-compiler.jar` fails with `AbstractMethodError` against the
   embeddable Compose plugin. The manual build now downloads
   `kotlin-compiler-embeddable-2.0.20.jar` into `tools/android-manual/dl/`.

## Known gaps (not hidden)

- **No live-Tor test.** The Arti runtime (bootstrap, onion service, stream
  routing, frame draining) is implemented and compiles, but no message has
  crossed the real Tor network in testing. First two-device test is the
  top priority for the next session.
- **No live-Tor voice call test (v0.3.0).** The call transport (signaling,
  media AEAD, onion-stream binding, audio engine) is implemented and unit
  tested, but no real call has run between two devices over Tor. Latency,
  jitter, audio quality and IP-leak behaviour on real phones are unverified.
- **Media encryption is not SRTP (v0.3.0).** ChaCha20-Poly1305 over RTP
  payloads with unique nonces, AAD binding and a replay window — a reviewed
  AEAD, but the construction as a whole is unreviewed. Needs the Phase 4
  audit before any production claim.
- **Call endpoint is the identity onion address in Phase 1 (v0.3.0).**
  No per-call ephemeral onion service — Arti 0.48 cannot create RAM-only
  service keys (TODO #1186, #1106). See `docs/CALLING_PHASE1.md` §1–2.
- **Opus is device-dependent (v0.3.0).** Some devices lack an Opus
  encoder/decoder; the call then fails honestly at start. No fallback codec.
- **No fuzzing run.** Skeleton exists (`rust-core/fuzz/`, 3 targets, all
  compile); no `cargo fuzz` run has executed.
- **No device run.** Nothing has run on a physical phone. Keystore levels,
  camera behaviour, Tor bootstrap time, and first-run UX are unverified.
- **Rust `.so` not built by Gradle.** The user must build it with
  `cargo ndk` and place it in `app/src/main/jniLibs/<abi>/` (README §Building).
- **ML-KEM Braid/SPQR not implemented** (needs incremental ML-KEM +
  erasure coding). DH+KEM step is the implemented mechanism.
- **No one-time prekey** (serverless design; see protocol doc §4).
- **Responder ratchet messages use a fresh outgoing connection** (extra Tor
  circuit; accepted stream's write half not retained in v0.1).

## Standing rules applied

- **Code-only delivery (user rule, 2026-11-08): no APK is built or sent.**
  The manual pipeline's local verification APK stays in its work directory
  and is never copied to `your_files/`. (A copied build script once wrote a
  verification APK over another project's file in `your_files/`; the script
  is fixed to output into its work directory only.)
- **Version pinning:** Compose family forced to 1.7.0, lifecycle family to
  2.8.4 in the manual verification build (the DocuDone lesson: mixed family
  versions cause `AbstractMethodError` at first composition). Gradle uses
  lifecycle 2.8.5 from the catalog.
- **Honesty:** EXPERIMENTAL labels stay on unreviewed components; the
  dashboard never shows green for an unimplemented feature.
