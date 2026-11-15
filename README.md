# ZeroTrace Messenger v0.3.0-experimental

**Private Communication. No Central Server. No Persistent Conversations.**

ZeroTrace Messenger is a one-to-one private messaging app for Android with a
WhatsApp-style interface and Tor-native voice calls. No phone number, no
email, no central account, no company messaging server, no cloud database,
no Firebase, no Google Sign-In. Each device generates its own cryptographic
identity; contacts are established by scanning an authenticated QR code;
messages and voice calls travel over Tor onion services; conversations live
only in volatile memory and disappear when the session ends.

> **EXPERIMENTAL — v0.3.0.** This is a working build, not a finished
> security product. The post-quantum handshake (PQXDH-Sync v1) is a new
> serverless construction with **no independent review**. The Tor integration
> compiles and its state machine is exercised, but **end-to-end messaging over
> the live Tor network has not been tested on two physical devices yet**,
> and **no live-Tor voice call has been tested yet either**. The ML-KEM and
> ML-DSA crates used are unaudited, and the media encryption (ChaCha20-
> Poly1305 over RTP payloads, not SRTP) is unreviewed. Do not rely on this
> app for safety-critical communication. See `docs/LIMITATIONS.md` and
> `DEVELOPMENT_STATUS.md` for the honest status of every component.

## What is implemented (v0.3.0)

- **WhatsApp-style UX**: Chats / Updates / Calls / Settings tabs, chat list
  with search, unread, mute and pin, full conversation screen (replies,
  reactions, copy with 30-second clipboard auto-clear, delete, message
  info, search in chat), contact profile with fingerprint verification,
  block / remove / rename, security dashboard, settings (theme, accent,
  app lock, session timeout, storage).
- **Voice calls (experimental, Phase 1)**: Tor-native transport — Opus
  audio (48 kHz, 20 ms frames) over the onion service, fresh 32-byte media
  key per call exchanged inside the ratchet-encrypted invite, RTP framing
  with ChaCha20-Poly1305 payload encryption, replay protection, real
  ringing / connecting / in-call states with timer, mute and speaker, and
  RAM-only call history. No media server, no TURN, no direct IP. See
  `docs/CALLING_PHASE1.md` for the design and the one deliberate deviation
  (Phase 1 uses the identity onion service, not a per-call service — Arti
  0.48 cannot create RAM-only service keys).
- **Identity**: Ed25519 + ML-DSA-87 identity keys, X25519 + ML-KEM-1024
  prekeys, generated in a Rust core (`rust-core/`), wrapped with the Android
  Keystore (StrongBox > TEE > software — the actual level is reported, never
  assumed).
- **Pairing**: versioned, authenticated QR commitment (~700 bytes). The QR
  carries the classical keys in full plus SHA-256 hashes of the PQ keys;
  full PQ keys are exchanged over Tor and verified against the hashes.
- **Handshake**: PQXDH-Sync v1 — a serverless adaptation of Signal PQXDH
  rev 3 (synchronous round trip over the onion channel, no one-time prekey).
- **Ratchet**: Signal Double Ratchet rev 4, with a fresh ML-KEM-1024
  encapsulation folded into the root KDF at every DH step (DH+KEM ratchet).
- **Transport**: Arti (Tor) only. Onion service per device, framed streams,
  fail-closed — no clearnet fallback, ever. One live session per contact.
- **Messages**: text, emoji, replies, reactions, real delivery/read
  receipts (encrypted acks), images, files (10 MB cap, chunked, SHA-256
  verified, offer/accept), voice notes (recorded to RAM via pipe — no temp
  file), in-app camera (captures to RAM — no photo file).
- **Status**: live-only — visible to connected peers while the session is
  live, never stored or relayed.
- **Ephemeral**: RAM-only chat history, per-conversation disconnect, automatic
  session timeout, FLAG_SECURE, no backups, no notification content, minimal
  permissions (camera for QR/photos, microphone for voice notes and calls,
  media read only when the user picks an attachment).

## What is NOT implemented (by design, v0.3.0)

Video calls (voice only in this release), groups (needs a reviewed group
protocol such as MLS), persistent history, offline message queue, cloud
sync. See `docs/LIMITATIONS.md`.

## Building

### Android app (Gradle — the supported path)

```bash
cd ZeroTraceMessenger
./gradlew assembleDebug
```

Requirements: Android SDK 35, JDK 17, Gradle 8.7 (wrapper included).
The Rust core must be built first — see below — and placed in
`app/src/main/jniLibs/<abi>/libzerotrace_core.so`.

### Rust core

```bash
cd rust-core
cargo test                 # 10 protocol/crypto tests, no network needed
cargo check --features tor # Arti integration (needs network for crates.io once)
cargo build --release --features tor
```

The `tor` feature is **off by default**; without it the app compiles but
messaging fails closed (Tor state ERROR). The release `.so` is produced with
`cargo ndk` (see `rust-core/README.md` if present, otherwise):

```bash
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../app/src/main/jniLibs build --release --features tor
```

### Compile verification without Gradle (this workspace)

The manual pipeline used here (kotlinc + aapt2, no Gradle) is documented in
`~/workspace/tools/android-manual/` — `resolver_zerotrace.py` resolves the
Maven graph, `build_zerotrace.py compile` runs aapt2 + kotlinc. This is a
verification aid only; the Gradle build is authoritative.

## Two-device test procedure

1. Build and install the app on two physical Android devices (minSdk 26).
2. On each device: create an identity, wait for Tor state
   `ONION_SERVICE_READY` (this can take 1–3 minutes on first run while Tor
   bootstraps and the onion service publishes).
3. On device A: **My QR** → show the pairing QR. On device B: **Add
   contact** → scan A's QR, compare the fingerprint in person, confirm.
   Repeat in the other direction (B's QR on A) so both sides hold a verified
   pairing.
4. On A: tap **Start chat** on B's contact. A sends its full bundle, B
   verifies it against the QR commitment and replies with its bundle, then
   the PQXDH handshake runs. Both sides should reach `E2EE_SESSION_READY`.
5. Exchange messages. Then **Disconnect — wipe this conversation** on either
   side and confirm the chat is gone from memory.
6. **Lock test**: press **Secure lock**; confirm the app returns to the home
   screen with Tor restarted and no messages retained.

Expected failure modes: if Tor cannot bootstrap (no network, Tor blocked),
the app shows `ERROR` and messaging stays disabled — that is the designed
fail-closed behaviour, not a bug to work around with clearnet.

## Project layout

```
app/                  Android app (Kotlin + Jetpack Compose, Material 3)
  src/main/java/com/zerotrace/messenger/
    bridge/           JNI bridge (RustCoreBridge) — opaque session handles only
    network/          TorState machine, foreground SessionService
    pairing/          QR commitment format + fingerprint
    security/         KeystoreManager, SecureWindowManager (FLAG_SECURE)
    session/          ZeroTraceViewModel (app state), ConversationState
                      (per-contact RAM state), FileProtocol (wire framing)
    ui/               screens: MainTabs, ChatScreen, ContactProfileScreen,
                      CallScreen, SettingsScreen, Onboarding, CameraScreen,
                      VoiceRecorder, QrScanner, QrUtil
    ui/components/    design system: TopBar, Avatar, ChatListItem,
                      MessageBubble, MessageComposer, AttachmentSheet,
                      SecurityInformationCard, states & badges
rust-core/            Rust security core (identity, crypto, handshake, ratchet,
                      Tor transport via Arti, JNI)
docs/                 threat model, architecture, protocol, security, privacy,
                      dependencies, limitations, architecture map (v2 audit),
                      UX upgrade security review
DEVELOPMENT_STATUS.md honest per-phase status + test evidence
```

## Security reporting

This is experimental software with unaudited components. If you find a
vulnerability, do not open a public issue — see `docs/SECURITY.md`.

## License

TBD — the project is not yet released under a license. Until one is chosen,
all rights are reserved by the author.
