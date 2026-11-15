# Privacy — ZeroTrace Messenger

## Data the app collects

**None.** There is no analytics, no telemetry, no crash reporting, no
advertising SDK, and no account of any kind. The app never sends data to the
developer or to any company server, because there is no server.

## Data on the device

| Data | Stored? | Where |
|---|---|---|
| Identity keys | Yes, wrapped | `identity.enc` (AES-GCM, Keystore key) |
| Contacts (onion, fingerprint, QR commitment) | Yes, encrypted | `contacts.enc` (same wrapping key) |
| Arti state (onion service key, Tor state) | Yes | App-private `arti/` directory |
| Messages | **No** | RAM only; wiped on disconnect / lock / timeout |
| Logs containing message content | **No** | Errors are reported without content |

## Data on the network

- All traffic goes through the Tor network (Arti client). The app opens no
  clearnet socket.
- The Tor network itself observes that the device uses Tor; the app does not
  claim to hide Tor usage.
- No DNS lookups are performed by the app (onion addresses are not DNS).
- QR pairing happens over the camera (local) and the Tor channel — no
  central contact discovery exists.

## Permissions

Camera (QR only), Internet, network state, foreground service, notifications.
No contacts, microphone, location, or storage permission.

## What the app cannot promise

- That Tor usage is invisible to an ISP or a global observer.
- That the OS, the carrier, or a compromised device does not observe more.
- That a peer's device keeps the conversation private — that is the peer's
  responsibility, and the app cannot enforce it.
