# ZeroTrace Messenger 2.0 — Architecture Map (v2 audit, 2026-11-15)

Internal audit done before the WhatsApp-style UX upgrade. Baseline verified
first: `cargo test` 10/10 pass (4 crypto + 6 protocol), Kotlin unit tests
22/22 pass, manual-pipeline compile of 71 classes clean (v1 delivery).

## 1. Android app (Kotlin + Jetpack Compose, AGP 8.5.2, Kotlin 2.0.21)

| File | Role | Security boundary |
|---|---|---|
| `MainActivity.kt` | Single activity. `Screen` enum navigation, `ZeroTraceTheme`, `SecureWindowManager` (FLAG_SECURE). | FLAG_SECURE on every screen. |
| `session/ZeroTraceViewModel.kt` | All app state. Identity load/create, Tor start/poll, `openSession` (initiator), accept loop (responder), receive loop, timeout watch, `lockAndDisconnect` (wipe). | **One live session at a time** (`sessionHandle: Long`), one global RAM `messages` list. Messages never touch disk/log. |
| `session/Screen` | SPLASH, ONBOARDING, CREATE_IDENTITY, HOME, MY_IDENTITY, ADD_CONTACT, VERIFY_CONTACT, CHAT, DASHBOARD, SETTINGS. | — |
| `ui/Screens.kt` | All screens in one file, plain Material 3, no design system. | Chat shows session label; dashboard shows only real status. |
| `ui/theme/Theme.kt` | Dark-only colour scheme (charcoal + green). | — |
| `pairing/PairingFormat.kt` | QR commitment v1 (~700 B): classical keys in full + SHA-256 of PQ keys + Ed25519 signature, 10-min expiry, strict parse. | Fingerprint must match Rust `Commitment::fingerprint`. |
| `data/ContactStore.kt` | Contacts in one AES/GCM file (`contacts.enc`), Keystore-wrapped. Never silently overwrites a changed fingerprint. | Contact identity is the QR commitment (`qrJson`), needed for bundle verification. |
| `security/KeystoreManager.kt` | Wrapping key, StrongBox > TEE > software; level exposed in diagnostics. | ML-KEM/ML-DSA keys never enter the Keystore (not supported); wrapped by hardware AES instead. |
| `network/SessionService.kt` | Foreground service while a session is active. Notification contains **no** content, names or fingerprints. | — |
| `network/TorState.kt` | 11 states OFFLINE…E2EE_SESSION_READY…ERROR; `canSend` rule. | Ready only after authenticated handshake. |
| `bridge/RustCoreBridge.kt` | JNI: `nativeTorStart(stateDir)`, `nativeBundleSend(onion, frameType, data)`, `nativeBindPeer/BindIncoming`, `nativeAcceptHandshake`, `nativeOpenSession`, `nativeHandshakeInit/Finish`, `nativeEncrypt/Decrypt`, `nativeTransportPoll/Send`, `nativeCloseSession`, `nativeTorStop`. | Opaque u64 handles; private keys never cross to Kotlin. |
| `ui/QrScanner.kt` | CameraX + ML Kit, QR only. Raw string is untrusted until `PairingFormat.parse` + Rust verification. | — |

Permissions (manifest): CAMERA, INTERNET, ACCESS_NETWORK_STATE,
FOREGROUND_SERVICE(+DATA_SYNC), POST_NOTIFICATIONS. No contacts/location/
storage/microphone yet — v2 adds RECORD_AUDIO + READ_MEDIA_* for attachments
and voice notes.

## 2. Rust core (`rust-core/`, Arti 0.48, `cargo test` 10/10)

| File | Role |
|---|---|
| `identity.rs` | Ed25519 + ML-DSA-87 identity, X25519 + ML-KEM-1024 prekeys. Bundle wire v1, BUNDLE_LEN 7553. |
| `handshake.rs` | **PQXDH-Sync v1** — serverless Signal PQXDH rev 3 adaptation, synchronous round trip, no one-time prekey. EXPERIMENTAL, unreviewed. |
| `ratchet.rs` | Double Ratchet rev 4 + fresh ML-KEM-1024 encapsulation folded into the root KDF at every DH step. ChaCha20-Poly1305 message AEAD. MAX_SKIP 1000. Braid/SPQR NOT implemented. |
| `tor.rs` | Real Arti runtime: tokio thread, onion service "zerotrace", framed streams `[type:1][len:4 BE][payload]` (B/I/R/M), max 1 MB. Fail-closed, no clearnet. |
| `session.rs` / `ffi.rs` | Opaque handles, MemoryTransport (tests), JNI surface. |
| `crypto.rs` | ML-KEM/ML-DSA/X25519/Ed25519/AEAD/HKDF wrappers. |

Verified: handshake bidirectional, tamper/replay rejected, out-of-order
delivery, QR commitment roundtrip, swapped-PQ-key rejection. Two ratchet bugs
found and fixed by tests (receiving step derives sending chain; decrypt
commits state only on AEAD success).

## 3. Known limitations (carried into v2 — do not paper over)

1. **Live Tor on two physical devices: NOT tested.** Arti runtime compiles;
   no message has crossed real Tor. The `.so` must be built by the user
   (`cargo ndk … --features tor` into `app/src/main/jniLibs/`).
2. **PQXDH-Sync v1 is experimental.** No one-time prekey, no independent review.
3. **ML-KEM Braid absent.** Per-message KEM ciphertext repeated in headers
   (~1.6 KB/message overhead).
4. **Both peers must be online simultaneously.** No offline queue, no relay.
5. **Single session at a time (v1).** v2 generalises this to one session per
   contact, kept in a map — the Rust core already supports multiple handles.
6. **RAM-only.** Process death wipes everything. No backup (`allowBackup=false`).
7. **Fuzz targets exist but `cargo-fuzz` has never been run.**

## 4. v2 design decisions (security-first, WhatsApp-style UX)

- **Navigation:** 4 tabs — Chats / Updates / Calls / Settings — plus stack
  screens (chat, contact profile, identity verification, attachment picker,
  media preview, call). Existing SPLASH/ONBOARDING/CREATE_IDENTITY flow kept.
- **Per-conversation RAM state:** conversations keyed by onion address;
  messages, unread, mute, pin live only in RAM. One Rust session per contact
  (map `onion -> handle`), each with its own receive loop and timeout watch.
  Closing a session wipes that conversation's messages (STRICT EPHEMERAL).
  Lock wipes everything.
- **Message framing (Kotlin, on top of the ratchet — no crypto change):**
  plaintext is `[type:1][payload]`; 0x01 text UTF-8, 0x02 file-offer JSON,
  0x03 file-chunk, 0x04 file-done, 0x05 status JSON. The ratchet still
  provides the AEAD; framing only multiplexes kinds. Old v1 clients only
  sent 0x01-less raw UTF-8 — v2 receive path accepts bare UTF-8 as text
  for backward compatibility within v2 builds (v1 is not a released peer).
- **File sharing:** chunked over the live ratchet channel (16 KiB chunks,
  10 MB cap), per-file SHA-256 integrity, offer/accept flow, no auto-save
  (SAF save dialog), received bytes held in RAM only. No temp files.
- **Voice notes:** MediaRecorder → pipe `FileDescriptor` (no plaintext file
  on disk) → bytes → file frame (kind audio). If the pipe fails on a device,
  recording reports failure honestly; no temp-file fallback.
- **Status/Updates:** live-only. My status is pushed to live sessions only;
  peer status is visible only while that session is live, then clears.
  No server, no persistence, no 24-hour promise.
- **Calls:** NOT implemented as real calls. Tor is TCP-only; WebRTC needs
  UDP/STUN/TURN/direct IP, which would break the anonymity model. The Calls
  tab, call screens and call history exist, but placing a call shows an
  honest EXPERIMENTAL/UNAVAILABLE state with the technical reason. No fake
  ringing, no fake connected state. Call history records only real attempts
  (outgoing attempts that hit the honest state) in RAM.
- **Groups:** disabled/planned only. No group crypto exists; reusing the 1:1
  ratchet for groups would be incorrect.
- **Archive:** not offered — incompatible with the RAM-only policy (an
  archived conversation would need persistent storage). Documented.
- **Mute/pin:** in-RAM session preferences (reset on process death).
- **Block:** stored flag in the encrypted contact store; blocked peers'
  bundles/handshakes are ignored in the accept loop.
- **Rename:** local-only display name, stored in the encrypted contact store.
- **UI prefs only in SharedPreferences:** theme, accent, my display name,
  mute flags are NOT stored there — mute/pin stay in RAM; theme/accent/name
  are UI preferences, never keys or messages.
- **Appearance:** dark / light / system theme + accent choice (green default).
- **App lock:** BiometricPrompt if available, otherwise honest unavailable state.
- **No new network, analytics, Firebase, or tracking dependencies.**
  New dep: `androidx.biometric:biometric:1.1.0` only.
