# Threat Model — ZeroTrace Messenger v0.1.0-experimental

## What this app is for

Two people who already know each other (they verify fingerprints in person)
want to exchange text messages without a central server, without an account,
and without a persistent conversation record on either device.

## Adversaries considered

| Adversary | What they can do | What the app does about it |
|---|---|---|
| Network observer (ISP, local network) | Sees that the device talks to the Tor network | All traffic goes through Arti/Tor; no clearnet sockets exist in the app. **Not claimed:** invisibility of Tor usage itself, or resistance to traffic correlation / timing analysis. |
| Malicious Tor relay / exit | Sees Tor cells | Onion services are end-to-end inside Tor; there is no exit relay in the path. Content is additionally E2EE. |
| Man-in-the-middle on the network | Injects / replays / tampers with traffic | Handshake and messages are authenticated (Ed25519 signatures, AEAD tags). Replays and tampering are rejected; a failed decrypt drops the message. |
| Peer impersonation | Pretends to be the contact | Identity is bound to the QR commitment verified in person; a bundle that does not match the commitment is rejected; a fingerprint change is never silently accepted. |
| Device thief (phone unlocked) | Reads the screen / app data | FLAG_SECURE, protected recents, no notification content, no backups. **Not claimed:** protection once the device is unlocked and the app is open — the messages are in RAM and readable by anyone holding the unlocked phone. |
| Device thief (phone locked) | Tries to extract data at rest | Identity is wrapped with a Keystore key (StrongBox > TEE > software; actual level reported). Contacts are stored encrypted. No message history is stored at all. |
| "Harvest now, decrypt later" (quantum) | Records ciphertext today, breaks classical crypto later | ML-KEM-1024 + ML-DSA-87 are used alongside the classical primitives, so a future quantum break of X25519/Ed25519 alone does not expose the handshake or the message keys. **Not claimed:** proof against a break of ML-KEM/ML-DSA themselves, or against implementation flaws in the unaudited crates. |

## Out of scope (explicitly NOT defended against)

- **A fully compromised device** (malware with root, or a live forensic
  acquisition of RAM). No software messenger can protect an already
  compromised endpoint. Root/integrity checks are informational only.
- **Physical coercion** (someone forcing the user to unlock the phone).
- **Traffic correlation by a global passive adversary** (ISP-level timing
  analysis of Tor usage). The app does not claim to defeat this.
- **Metadata beyond the network**: the app has no analytics and no
  telemetry, but the OS, the carrier and the Tor network itself still
  observe coarse facts (device online, Tor in use).
- **Endpoint compromise via the peer**: if the other person's device is
  compromised, the conversation is compromised. There is no way around this.
- **Implementation bugs in the crypto crates or in Arti.** The crates used
  are unaudited at these versions; the handshake construction is unreviewed.
  See `docs/DEPENDENCIES.md`.

## Assumptions the design relies on

1. The two users verify fingerprints **in person or over an already-trusted
   channel**. If the QR is exchanged over an untrusted channel, the whole
   pairing is untrustworthy.
2. The Android Keystore on the device actually enforces its security level
   (the app reports the level it gets; it does not verify the hardware).
3. The Tor network is reachable. If it is not, the app fails closed — there
   is no fallback, and therefore no messaging.
4. Both peers are online at the same time. There is no store-and-forward.
