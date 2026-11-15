# Architecture — ZeroTrace Messenger v0.1.0-experimental

## Layers

```
┌────────────────────────────────────────────────────────────┐
│  UI (Kotlin + Jetpack Compose, Material 3)                 │
│  Screens.kt — 10 screens, all state via StateFlow          │
├────────────────────────────────────────────────────────────┤
│  ViewModel (ZeroTraceViewModel)                            │
│  App state machine: identity, contacts, Tor, sessions      │
│  RAM-only messages; single destruction path                │
├────────────────────────────────────────────────────────────┤
│  Bridge (RustCoreBridge, JNI)                              │
│  Opaque u64 session handles; private keys never cross      │
├────────────────────────────────────────────────────────────┤
│  Rust core (libzerotrace_core.so)                          │
│  identity / crypto / handshake / ratchet / session / tor   │
├────────────────────────────────────────────────────────────┤
│  Transport (Arti, feature `tor`)                           │
│  TorClient bootstrap, onion service, framed streams        │
└────────────────────────────────────────────────────────────┘
```

## Rust core modules (`rust-core/src/`)

| Module | Responsibility |
|---|---|
| `identity.rs` | Identity generation, bundle serialisation (v1, fixed offsets), QR commitment creation/verification, fingerprint |
| `crypto.rs` | ML-KEM-1024, ML-DSA-87, X25519, Ed25519, HKDF, ChaCha20-Poly1305 wrappers |
| `handshake.rs` | PQXDH-Sync v1 initiator/responder |
| `ratchet.rs` | Double Ratchet rev 4 + DH+KEM step, skipped-key store, replay protection |
| `session.rs` | Session state machine, opaque handles, MemoryTransport (tests), TorTransport |
| `tor.rs` | TorManager (queues + state), Arti runtime (Tokio thread, onion service, stream routing, frame draining) |
| `ffi.rs` | JNI exports; every error becomes a Java RuntimeException |

## Tor runtime design

- One background OS thread runs a Tokio multi-thread runtime. All Tor I/O
  happens there; the synchronous `TorManager` only holds queues.
- `TorClient::create_bootstrapped` from an app-private state directory
  (`filesDir/arti`); cache in `filesDir/arti-cache`.
- Onion service nicknamed `zerotrace`; its address comes from the service's
  `HsId` — never from configuration.
- Incoming rendezvous requests are accepted and their streams are read by
  per-connection tasks. Outgoing connections are opened on demand and cached
  per onion address / per session handle.
- Frame routing: `B`/`I`/`R` frames go to the bundle queue (the Kotlin
  accept/open flows consume it); `M` frames go to the session handle's
  inbound queue, resolved by peer-onion (initiator) or by the initiator's
  Ed25519 key (responder, bound after `nativeAcceptHandshake`).
- The responder's own ratchet messages go out on a **fresh outgoing**
  connection to the peer onion (the accepted stream's write half is not
  retained in v0.1). This costs an extra Tor circuit per session, not a
  correctness problem.
- Stop: `stop_requested` is observed by the drain loop (100 ms poll); the
  runtime thread then exits and clears `arti_running`. Restart waits up to
  5 s for the previous thread to exit.

## Android state machine (`TorState`)

```
OFFLINE → INITIALIZING → TOR_BOOTSTRAPPING → TOR_READY
  → ONION_SERVICE_STARTING → ONION_SERVICE_READY
  → CONNECTING_TO_PEER → AUTHENTICATING_PEER → E2EE_SESSION_READY
  → DISCONNECTING → OFFLINE
  (any failure → ERROR; messaging is disabled unless the state is one of
   the ready/connecting states)
```

The UI only enables "Start chat" when the state is
`ONION_SERVICE_READY`. A session is "ready" only after the authenticated
handshake completes — never on Tor readiness alone.

## Data at rest

| Data | Where | Protection |
|---|---|---|
| Identity bundle | `filesDir/identity.enc` | AES-256-GCM, key in Android Keystore (StrongBox > TEE > software) |
| Contacts | `filesDir/contacts.enc` | Same wrapping key, one AES/GCM blob |
| Arti state (onion key, descriptors) | `filesDir/arti/` | App-private directory; Arti-managed |
| Messages | **nowhere** — RAM only | Cleared on disconnect / lock / timeout |
| Backups | excluded | `allowBackup=false`, backup rules exclude everything |

## Permissions

CAMERA (QR scanning only), INTERNET, ACCESS_NETWORK_STATE,
FOREGROUND_SERVICE (+DATA_SYNC), POST_NOTIFICATIONS. No contacts,
microphone, location or storage permission is requested.
