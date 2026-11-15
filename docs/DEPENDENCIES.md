# Dependencies — ZeroTrace Messenger v0.1.0-experimental

Every dependency was checked for maintenance status, known vulnerabilities
and licence on 2026-11-15 (via crates.io / Maven Central). "Unaudited"
means: no published independent security audit was found for that crate at
that version. Unaudited does not mean broken — it means unreviewed, and the
app must not be described as audited.

## Rust core (`rust-core/Cargo.toml`)

| Crate | Version used | Latest at check | Audit / notes |
|---|---|---|---|
| `ml-kem` | 0.2 | 0.3.4 | **Unaudited.** FIPS 203 ML-KEM-1024. Pure Rust. |
| `ml-dsa` | 0.1 | 0.1.2 | **Unaudited.** FIPS 204 ML-DSA-87. Pure Rust. |
| `kem` | 0.3.0-pre.0 | — | Direct dependency: `ml-kem` re-exports the KEM traits only privately. |
| `x25519-dalek` | 2 | 3.0.0 | Widely used; `dalek` crates have had audits of earlier versions. |
| `ed25519-dalek` | 2 | 3.0.0 | Same as above. |
| `chacha20poly1305` | 0.10 | 0.11.0 | RustCrypto AEAD, widely used. |
| `hkdf`, `hmac`, `sha2` | RustCrypto | — | Standard RustCrypto primitives. |
| `zeroize` | — | — | Used for wiping secret material. |
| `arti-client` | 0.48 | 0.48.0 | Tor's official Rust client (Arti). Under active development; onion-service API is experimental. |
| `tor-hsservice`, `tor-cell`, `tor-rtcompat` | 0.48 | 0.48.0 | Arti companion crates, same status. |
| `tokio` | 1 | — | Async runtime for the Arti thread. |
| `jni` | 0.21 | 0.22.4 | JNI bindings. |
| `safelog`, `futures` | 0.10 / 0.3 | — | Arti support crates / stream helpers. |

**Deliberately NOT used:** `pqc_kyber`, `pqcrypto` (pre-standard Kyber,
KyberSlash RUSTSEC-2023-0079).

## Android app (`gradle/libs.versions.toml`)

| Dependency | Version | Notes |
|---|---|---|
| AGP / Gradle / Kotlin | 8.5.2 / 8.7 / 2.0.21 | Standard. |
| Compose BOM | 2024.09.00 (Compose 1.7.0) | UI. |
| `androidx.core:core-ktx` | 1.13.1 | |
| `androidx.activity:activity-compose` | 1.9.2 | |
| `androidx.lifecycle:*` | 2.8.4 (manual build) / 2.8.5 (Gradle catalog) | Family versions forced together — see the DocuDone lesson in `DEVELOPMENT_STATUS.md`. The 2.8.4/2.8.5 difference is a verification-build pin only; the Gradle build uses 2.8.5. |
| CameraX (`camera-core/camera2/lifecycle/view`) | 1.3.4 | QR scanning. |
| ML Kit `barcode-scanning` | 17.3.0 | On-device QR decoding (Play-services-delivered, on-device). |
| ZXing `core` | 3.5.3 | QR generation. |
| JUnit | 4.13.2 | Unit tests only. |
| `org.json:json` | 20240303 | **Unit tests only** — android.jar's org.json is a stub on the JVM. The app uses Android's built-in org.json at runtime. |

## What the app does NOT depend on

No Firebase, no Google Sign-In, no Play-services auth, no Room, no Hilt, no
Retrofit/OkHttp, no analytics or crash-reporting SDK. The only Google
Play-services code that ships is the ML Kit barcode-scanning runtime
dependency (on-device, no account, no network use by the app).
