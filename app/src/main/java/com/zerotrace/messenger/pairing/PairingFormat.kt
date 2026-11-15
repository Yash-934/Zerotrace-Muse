package com.zerotrace.messenger.pairing

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Versioned, authenticated QR pairing format — ZeroTrace-Pairing-v1 (commitment).
 *
 * WHY A COMMITMENT: a QR code cannot hold post-quantum keys. ML-DSA-87's public
 * key alone is 2592 bytes and its signature 4627 bytes — far beyond QR capacity
 * (~3 KB). So the QR carries the classical identity keys in full, plus SHA-256
 * hashes of the two PQ public keys, all signed with Ed25519. The full PQ keys
 * are exchanged afterwards over the Tor channel and verified against these
 * hashes by the Rust core (`nativeVerifyBundle`). A peer presenting different
 * PQ keys than the QR committed to is rejected.
 *
 * The QR is ~700 bytes and fits a normal QR code.
 */
object PairingFormat {
    const val PROTOCOL_ID = "zt"
    const val VERSION = 1
    const val EXPIRY_SECONDS = 600L // pairing QR lives 10 minutes
    const val MAX_QR_BYTES = 8192

    data class Bundle(
        val onionAddress: String,
        val identityEd25519: String, // hex, 32 bytes
        val identityX25519: String, // hex, 32 bytes
        val signedPrekeyX25519: String, // hex, 32 bytes
        val pqIdentityHash: String, // hex, SHA-256 of the ML-DSA-87 verifying key
        val pqPrekeyHash: String, // hex, SHA-256 of the ML-KEM-1024 encapsulation key
        val signatureEd25519: String, // hex, 64 bytes
        val expiryEpochSeconds: Long,
        val nonce: String, // hex, 16 bytes
        val capabilities: List<String>,
        val rawJson: String
    )

    sealed class ParseResult {
        data class Ok(val bundle: Bundle) : ParseResult()
        data class Invalid(val reason: String) : ParseResult()
    }

    fun parse(raw: String): ParseResult {
        if (raw.length > MAX_QR_BYTES) return ParseResult.Invalid("QR too large")
        val json = runCatching { JSONObject(raw) }.getOrElse {
            return ParseResult.Invalid("not JSON")
        }
        if (json.optString("p") != PROTOCOL_ID) return ParseResult.Invalid("unknown protocol")
        if (json.optInt("v", -1) != VERSION) return ParseResult.Invalid("unsupported version")
        fun hexField(name: String, expectedBytes: Int): String? {
            val v = json.optString(name)
            if (v.length != expectedBytes * 2 || !v.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            return v.lowercase()
        }
        val now = System.currentTimeMillis() / 1000
        val expiry = json.optLong("exp", 0)
        if (expiry <= now) return ParseResult.Invalid("pairing QR expired")
        if (expiry - now > EXPIRY_SECONDS + 60) return ParseResult.Invalid("expiry too far in future")
        val onion = json.optString("onion")
        if (!onion.endsWith(".onion") || onion.length != 62) return ParseResult.Invalid("bad onion address")
        val bundle = Bundle(
            onionAddress = onion,
            identityEd25519 = hexField("ik_ed", 32) ?: return ParseResult.Invalid("bad ik_ed"),
            identityX25519 = hexField("ik_x", 32) ?: return ParseResult.Invalid("bad ik_x"),
            signedPrekeyX25519 = hexField("spk_x", 32) ?: return ParseResult.Invalid("bad spk_x"),
            pqIdentityHash = hexField("pq_id_hash", 32) ?: return ParseResult.Invalid("bad pq_id_hash"),
            pqPrekeyHash = hexField("pq_ek_hash", 32) ?: return ParseResult.Invalid("bad pq_ek_hash"),
            signatureEd25519 = hexField("sig_ed", 64) ?: return ParseResult.Invalid("bad sig_ed"),
            expiryEpochSeconds = expiry,
            nonce = hexField("nonce", 16) ?: return ParseResult.Invalid("bad nonce"),
            capabilities = runCatching {
                val arr = json.getJSONArray("caps")
                List(arr.length()) { arr.getString(it) }
            }.getOrElse { return ParseResult.Invalid("bad caps") },
            rawJson = raw
        )
        if (!bundle.capabilities.contains("pqxdh-sync-v1")) {
            return ParseResult.Invalid("peer does not support pqxdh-sync-v1")
        }
        return ParseResult.Ok(bundle)
    }

    /**
     * Fingerprint users compare: SHA-256 over the classical identity key, the
     * two PQ-key hashes and the onion address — computable from the QR alone.
     * Must match the Rust core's `Commitment::fingerprint` exactly.
     */
    fun fingerprint(bundle: Bundle): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(hexToBytes(bundle.identityEd25519))
        digest.update(hexToBytes(bundle.pqIdentityHash))
        digest.update(hexToBytes(bundle.pqPrekeyHash))
        digest.update(bundle.onionAddress.toByteArray(Charsets.UTF_8))
        val hash = digest.digest()
        val hex = hash.take(24).joinToString("") { b -> "%02x".format(b) }
        return hex.chunked(4).joinToString(" ")
    }

    fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
