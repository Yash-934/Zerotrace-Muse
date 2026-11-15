# ZeroTrace Calling — Phase 1: Tor-native voice calls (v0.3.0-experimental)

Date: 2026-11-15. This document is the design record for real voice calling
in ZeroTrace. It records what the user proposed, what the Arti 0.48 audit
actually found, the one deliberate deviation from the proposal, and the exact
construction implemented. Nothing here claims a test that did not run.

## 0. The user's proposal (accepted in substance)

Voice first, then video. Tor-native TCP transport, no central media server,
no public TURN, no direct-IP fallback. Signaling over the existing ratchet.
Fresh per-call identity and media keys. Authenticated media encryption with
a reviewed construction (no invented crypto). Honest about Tor latency.

Correction accepted: WebRTC does NOT require UDP or direct IP — ICE-TCP and
TURN over TCP/TLS are standardized. The reason calls were "unavailable" in
v0.2.0 was never that TCP can't carry media; it was that no call transport
existed in the app at all.

## 1. What the Arti 0.48 audit found (ground truth, not docs)

Checked against the vendored `arti-client 0.48.0` / `tor-hsservice 0.48.0`
sources in `~/.cargo/registry`, and against the existing `tor.rs`.

1. **Multiple onion services on one client are possible.** `TorClient::
   launch_onion_service` builds a fresh `OnionService` per call; nothing
   prevents a second service with a different nickname.
2. **Truly ephemeral (RAM-only) service keys are NOT possible in 0.48.**
   The source itself says so:
   - `client.rs`, `launch_onion_service`: `// TODO #1186: Allow override
     of KeyMgr for "ephemeral" operation?`
   - `launch_onion_service_with_hsid` (gated behind the `experimental-api`
     feature, which this project does NOT enable): "The specified
     `HsIdKeypair` will be inserted in the primary keystore" and
     "depending on the configuration of your primary keystore, the
     `HsIdKeypair` **may** get persisted to disk. By default, Arti's
     primary keystore is the [native], disk-based keystore."
   - Custom/non-default keystores are not supported yet (see #1106, quoted
     in `generate_service_discovery_key`).
   
   Consequence: a "temporary onion service per call" in 0.48 would write a
   persistent service key to disk in the Arti state dir for every call.
   That directly violates the proposal's own requirement ("Private key RAM
   mein rahegi") and the app's RAM-only discipline.

## 2. The one deliberate deviation (Phase 1)

**Phase 1 does NOT create a per-call onion service.** Calls run over the
existing long-lived "zerotrace" onion service, with:

- a **one-time callId** (16 random bytes, fresh per call, never reused),
- a **fresh 32-byte media key** per call (Rust OsRng, exchanged inside the
  ratchet-encrypted invite — see §4),
- media streams authenticated by callId + media key, and
- all call state (keys, buffers, SSRCs, sequence windows) zeroed and
  dropped when the call ends.

What this gives up vs the proposal: the call endpoint is the identity's
onion address, so the *peer* (who already knows that address — it is the
contact's pairing channel) can link the call to the identity. A network
observer sees Tor circuits, not the service identity, and media content
stays protected by the fresh per-call key even if the service key is later
compromised. What it avoids: writing a persistent key file to disk for
every call, and depending on an experimental Arti API.

**Phase 1.1 (future, blocked on Arti):** per-call ephemeral onion services
once Arti supports in-memory service keys (TODO #1186 / #1106, or an
audited keystore-removal path for the per-call nickname). The transport
code is structured so the service address is a parameter, not a constant,
so the swap is a transport change, not a protocol change.

## 3. Signaling (over the existing ratchet — no new trust)

New `WireFrame` types (Kotlin, inside the ratchet plaintext — the ratchet
still provides all encryption and authentication):

| Type | Byte | Payload (JSON) |
|---|---|---|
| CALL_INVITE | 0x0B | `{id, key, caps:["opus"], audio:true}` — id/key are base64 (16B callId, 32B media key) |
| CALL_ACCEPT | 0x0C | `{id}` |
| CALL_DECLINE | 0x0D | `{id}` |
| CALL_END | 0x0E | `{id}` |

Rules:
- An invite is only ever sent on a live, verified session (the ratchet
  authenticates the peer; a stranger cannot invite).
- Invite expiry 60 s (ring timeout → missed-call record, no silent queue).
- One active call at a time per device. An invite arriving while busy is
  answered with CALL_DECLINE immediately (documented, not silent).
- The callee's phone "rings" only when a real invite arrives. No fake
  ringing, no fake connected state.
- CALL_END is best-effort (the peer's timeout also ends the call); ending
  locally always tears down local state first.

## 4. Media keys

- Caller: Rust `nativeCallBegin()` generates callId (16B) + media key
  (32B) from OsRng, registers the call in the Rust core, returns both to
  Kotlin. Kotlin puts them in the invite JSON (inside the ratchet).
- Callee: on accepting, Kotlin calls Rust `nativeCallJoin(callId,
  mediaKey)` to register the same call state.
- The media key crosses JNI exactly once in each direction (same pattern
  as the identity bundle crossing; documented in `ffi.rs`). It is never
  stored, never logged, zeroed on call end (`zeroize`).
- Direction separation is by nonce, not by key: one key, nonces carry a
  direction byte (caller→callee 0xA1, callee→caller 0xB2), so a reflected
  frame can never decrypt as the other direction's frame.

## 5. Media transport (Rust core, `call.rs` + `tor.rs`)

Onion-stream framing is the existing `[type:1][len:4 BE][payload]`; new
frame types:

| Type | Byte | Payload |
|---|---|---|
| CALL_HELLO | 0x43 'C' | callId (16B) — first frame on a call stream, binds it |
| CALL_MEDIA | 0x41 'A' | one RTP packet (see below) |

Inside a CALL_MEDIA payload is a standard RTP packet (RFC 3550):
12-byte header (V=2, PT=96 dynamic/Opus, per-direction 16-bit sequence,
32-bit timestamp at 48 kHz, per-direction 32-bit SSRC) + encrypted payload.

Payload encryption is **ChaCha20-Poly1305** (the crate already in the
core — no new primitive, no invented construction):
- key: the per-call media key,
- nonce (12B): `[direction:1][SSRC:4][seq:2][timestamp:4][0x00:1]` —
  unique per key per packet by construction (SSRC differs per direction,
  seq increments),
- AAD: `callId || "zt-call-media-v1" || RTP header` — binds the header
  (sequence/timestamp/SSRC) to the ciphertext, so tampering with the
  header fails authentication,
- replay protection: per-direction highest-seq + 64-bit window (SRTP-style;
  duplicates and old packets are dropped, never delivered to the decoder).

Length framing note: RFC 4571 specifies a 2-byte length prefix for RTP
over TCP. The onion stream's existing 4-byte length prefix performs the
same function; adding a second prefix inside would be redundant. The RTP
packets themselves are standard. This is a documented simplification, not
a second framing.

Transport changes in `tor.rs` (the v0.1 accept loop dropped the write
half of accepted streams — calls need it):
- Accepted streams: the first frame decides the stream kind. CALL_HELLO
  with a known pending callId binds the stream (both halves retained) to
  that call; anything else follows the existing bundle/session routing.
- `TorManager` gains call queues: `call_outbound` (encrypted media frames
  to send, per callId), `call_inbound` (decrypted Opus frames to poll, per
  callId), `call_connect` (pending outgoing call connections: callId →
  onion). The drain loop connects, sends CALL_HELLO, retains the stream,
  and drains `call_outbound` onto it.
- Reader tasks decrypt media frames through `call.rs` and push Opus bytes
  to `call_inbound`. A failed AEAD open drops the frame and counts it
  (never delivered, never crashes the stream).

## 6. Audio pipeline (Kotlin, `session/CallAudio.kt`)

- Capture: `AudioRecord`, `VOICE_COMMUNICATION`, 48 kHz mono PCM16,
  20 ms frames (960 samples).
- Codec: Opus via `MediaCodec("audio/opus")`, 48 kHz, 1 channel,
  24 kbit/s. **Runtime capability check**: the encoder/decoder are
  queried from `MediaCodecList` at call start; if Opus is absent on the
  device, the call fails honestly with "Opus not available on this device"
  — there is deliberately no fallback codec in Phase 1.
- Echo cancellation / noise suppression: `AcousticEchoCanceler` and
  `NoiseSuppressor` attached to the AudioRecord session **if the device
  reports them available**; otherwise the call proceeds and the limitation
  is shown in the call screen (honest, not silent).
- Playback: `AudioTrack`, `STREAM_VOICE_CALL`, 48 kHz mono. Small jitter
  buffer (Kotlin): frames older than ~200 ms are dropped; the buffer is
  capped so a stall cannot build unbounded latency.
- Threads: capture thread (record → encode → `nativeCallSendAudio`),
  playback thread (`nativeCallPollAudio` → decode → write). Both stop on
  call end; buffers are RAM-only.
- Permissions: `RECORD_AUDIO` (already declared in v0.2.0) +
  `MODIFY_AUDIO_SETTINGS` (normal permission, for the speakerphone toggle).

## 7. Call states (Kotlin ViewModel — all real)

`Idle → Outgoing (invite sent, ringing the peer) → Connecting (onion
stream establishing) → InCall (timer runs only here) → Ended`. Incoming:
`Incoming (real invite, ringing) → Connecting → InCall`. Any failure
(Tor not ready, Opus missing, peer declined, timeout, stream loss) lands
in `Ended(reason)` with the reason shown — never a fake connected state.
Mic mute (capture pause) and speaker toggle are real controls. Call
history (`CallRecord`) records only real calls: connected duration for
answered calls, "missed" for unanswered invites, "unavailable" only for
the pre-Phase-1 placeholder (gone in v0.3.0).

## 8. Honest limits (Phase 1)

- **Latency is not WhatsApp-like.** Tor rendezvous + 3-hop circuits +
  TCP retransmissions: expect noticeable delay and occasional audio gaps.
  The call screen shows a live "experimental — expect delay" note.
- **Audio-only.** Video is Phase 3 of the user's roadmap, not this release.
- **One call at a time.** Second incoming call is declined, not queued.
- **Opus is device-dependent.** Some devices lack an Opus encoder; the
  call then fails honestly at start.
- **No live-Tor call test has run yet** in this environment (same standing
  gap as messaging). First real-device call test is the top priority after
  this lands.
- **Media encryption is ChaCha20-Poly1305 over RTP payloads, NOT SRTP.**
  It reuses a reviewed AEAD with unique nonces + AAD binding + replay
  window, but the construction as a whole has no independent review. The
  user's Phase 4 audit must cover it before any production claim.
- **The call endpoint is the identity onion address in Phase 1** (§2).
  Per-call ephemeral services are Phase 1.1, blocked on Arti #1186/#1106.
- **No call recording, no voicemail, no call metadata storage.** Call
  history is RAM-only like everything else; ending a call wipes its keys
  and buffers.
