# ZeroTrace Messenger 2.0 — UX Upgrade Security Review (2026-11-15)

> **Update (v0.3.0, 2026-11-15):** the "Calls" section below (§2, "Calls
> (NOT implemented)") is superseded — Tor-native voice calling is now
> implemented (Phase 1). See `docs/CALLING_PHASE1.md` for the design, the
> Arti 0.48 audit, and the one deliberate deviation (identity onion service
> instead of a per-call service). Everything else in this review still stands.

WhatsApp-style usability upgrade of the v0.1.0-experimental codebase. This
document is the Phase 5 security review required by the upgrade brief: what
changed, what was preserved, what is new, what is honestly unavailable, and
what must never be mistaken for a security guarantee.

## 1. What was preserved (untouched)

- **Rust core** (`rust-core/`): identity, PQXDH-Sync v1 handshake, Double
  Ratchet + per-step ML-KEM, Tor/Arti runtime, JNI surface — **zero changes**.
  `cargo test` still 10/10.
- **Cryptographic boundaries**: private keys never leave the Rust core;
  Keystore wrapping (StrongBox > TEE > software) unchanged; QR commitment
  format v1 unchanged; bundle verification unchanged; fail-closed Tor
  routing unchanged; no clearnet fallback anywhere.
- **Storage policy**: messages RAM-only; contacts in one AES/GCM file;
  `allowBackup=false`; FLAG_SECURE on every screen; notification contains
  no content, names or fingerprints.
- **No new network, analytics, Firebase, or tracking dependency.** The only
  new Gradle dependency is `androidx.compose.material:material-icons-extended`
  (UI icons, no network, no telemetry).

## 2. What changed (Kotlin only)

### Navigation
Four tabs — Chats / Updates / Calls / Settings — plus stack screens (chat,
contact profile, call, dashboard, settings, identity, add contact). The
onboarding/identity-creation flow is unchanged.

### Per-conversation sessions (the core v2 change)
v1 held ONE live session and ONE global message list. v2 holds one
`Conversation` per verified contact (RAM only) and one Rust session per
contact (`onion -> handle`), each with its own receive loop and timeout
watch. The Rust core already supported multiple handles; the Kotlin side
now uses them. Closing a session still wipes that conversation's messages;
Lock still wipes everything. Global Tor state is derived from the live
sessions (`refreshGlobalTorState`).

**Security implication:** more concurrent sessions = more concurrent onion
streams. No new trust is introduced: each session is still independently
authenticated against the QR commitment, and each has its own ratchet.

### Message framing (`session/FileProtocol.kt`)
Plaintext inside the ratchet is now `[type:1][payload]`:
0x01 text (with shared 8-byte msgId), 0x02 file-offer JSON, 0x03 file-chunk,
0x04 file-done, 0x05 status JSON, 0x06/0x07 delivery/read acks, 0x08
reaction, 0x09/0x0A file accept/decline. **The ratchet still provides all
encryption and authentication; framing only multiplexes kinds.** No crypto
change, no new protocol. Legacy bare UTF-8 is accepted as text (v1 was
never a released peer; defence-in-depth only).

**Handshake race fixed in passing:** `openSession` used to accept ANY
non-JSON bundle frame as the handshake response. A peer's Init frame
(1600+ bytes, starts 0x01) arriving mid-handshake could have been mistaken
for the response. v2 accepts only a 64-byte frame as the response (the
response is exactly 32-byte ratchet key + 32-byte confirmation). Verified
against `handshake.rs` (`responder_respond`, `initiator_finish`).

### Delivery/read receipts (real, not faked)
The receiver sends an encrypted ACK_DELIVERED on receipt and ACK_READ when
the chat is open. Ticks in the UI (✓ sent, ✓✓ delivered, ✓✓ green read)
reflect these real acks. No receipt is ever shown for a message that was
not acknowledged.

### File sharing (real, over the ratchet)
- Offer → explicit user accept/decline → 16 KiB chunks → SHA-256 verified
  reassembly in RAM → message appears. Declined or interrupted transfers
  leave nothing behind (partial chunks are discarded, never shown).
- Limits: 10 MB per file, MIME allowlist (image/video/audio/text + PDF/
  Office/ZIP), file names sanitised (path separators stripped, display-only
  — never used as a path), no auto-save (SAF save dialog, user-chosen name).
- Received bytes live in RAM only until the user saves or the session ends.
- **No temporary files** for transfers.

### Voice notes (real, no temp file)
MediaRecorder writes to a pipe `FileDescriptor`; bytes stream straight into
RAM and are sent as a file frame. If the device refuses the pipe, recording
fails honestly — there is deliberately no temp-file fallback.

### Camera (real, no temp file)
In-app CameraX screen; `ImageCapture` delivers an in-memory `ImageProxy`
(YUV_420_888 → JPEG bytes in RAM). No photo file is ever written.

### Status / Updates (live-only — honest)
My status is pushed to live sessions only; a peer's status is visible only
while that session is live, then it clears. No server, no persistence, no
24-hour promise. The UI says this explicitly.

### Calls (NOT implemented — honest)
The Calls tab, call history and call screen exist, but placing a call shows
an EXPERIMENTAL/UNAVAILABLE state with the technical reason (Tor is
TCP-only; WebRTC needs UDP/STUN/TURN/direct IP, which would reveal the
user's real IP to the peer). No ringing, no fake connection, no fake timer.
Call history records only real attempts (RAM-only) as "unavailable".

### Groups (disabled, by design)
"New group" shows a dialog: groups need a reviewed group E2EE protocol
(e.g. MLS). Reusing the 1:1 ratchet for groups would be incorrect.

### Archive (not offered)
Incompatible with the RAM-only policy — an archived conversation would need
persistent storage. Documented; no fake archive.

### Contact management (real)
Rename (local-only, encrypted store), mute/pin (RAM-only session prefs),
block (stored flag; blocked peers' bundles and handshakes are ignored in
the accept loop; blocking ends a live session), remove (deletes from the
encrypted store + ends the session).

### Settings (real)
- Theme: dark / light / system + accent (green/teal/emerald). UI prefs in
  SharedPreferences — **never keys or messages**.
- App lock: device PIN/pattern/password via KeyguardManager (no new dep).
- Clipboard: copied text auto-cleared after 30 s.
- Session timeout: 5/10/30 min, per-conversation.
- Storage screen shows real counts (contacts, live sessions, messages in
  RAM) and the retention policy.
- Security Dashboard: same honest per-component status as v1, extended with
  file transfer / voice notes / calls / groups rows.

## 3. New permissions (manifest)
- `RECORD_AUDIO` — voice notes only (runtime request at first use).
- `READ_MEDIA_IMAGES/VIDEO/AUDIO` — only when the user picks an attachment
  (the app never scans media in the background).
- No contacts, location, or storage permission. No new exported components.

## 4. What is still NOT verified (same as v1 — unchanged)
- Live Tor messaging on two physical devices.
- PQXDH-Sync v1: experimental, no independent review, no one-time prekey.
- ML-KEM Braid absent (~1.6 KB/message header overhead).
- `cargo-fuzz` never run (targets exist).
- Gradle build here is not possible (no Gradle CLI); the user builds in
  Antigravity. Kotlin is compile-verified via the manual pipeline.
- UI text is English-only in v2 (localisation debt carried from v1; the
  Hindi strings file exists but the UI never used string resources).

## 5. Threat-model deltas introduced by v2
1. **More live sessions** — each is independently authenticated; the
   accept loop now runs while other sessions are live (v1 paused it during
   `openSession` only). Incoming handshakes from blocked contacts are
   dropped before any crypto runs.
2. **File metadata** — the peer sees file names, sizes, MIME types and
   SHA-256 hashes (needed for the transfer). File names are user-chosen;
   users should avoid sensitive names. Documented in the attachment sheet.
3. **Delivery/read receipts** — the peer learns when a message was
   delivered and read (standard messenger metadata, inherent to the feature).
4. **Status** — a status is visible to every live session peer (audience
   selection is not yet implemented; the audience set exists in code but is
   not exposed in the UI — v2 ships "all live peers").
5. **No new trust in any third party.** No server, no relay, no push.

## 6. What was NOT done (and why)
- No WebRTC / real calls: would break the anonymity model (see §2 Calls).
- No group crypto: no reviewed implementation available in-tree.
- No offline queue / relay: would need a server or a store-and-forward
  relay, both out of scope for STRICT EPHEMERAL MODE.
- No message backup / export: incompatible with the ephemeral policy.
- No FCM / push: incompatible with the privacy model.
