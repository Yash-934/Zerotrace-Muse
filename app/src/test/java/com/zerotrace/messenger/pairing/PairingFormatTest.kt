package com.zerotrace.messenger.pairing

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the QR commitment parser. These run on the JVM (no Android
 * framework needed) — PairingFormat only uses org.json + java.security.
 */
class PairingFormatTest {

    private fun validQr(expiresInSeconds: Long = 600): String {
        val exp = System.currentTimeMillis() / 1000 + expiresInSeconds
        val onion = "a".repeat(56) + ".onion"
        return JSONObject().apply {
            put("p", "zt")
            put("v", 1)
            put("onion", onion)
            put("ik_ed", "11".repeat(32))
            put("ik_x", "22".repeat(32))
            put("spk_x", "33".repeat(32))
            put("pq_id_hash", "44".repeat(32))
            put("pq_ek_hash", "55".repeat(32))
            put("sig_ed", "66".repeat(64))
            put("exp", exp)
            put("nonce", "77".repeat(16))
            put("caps", org.json.JSONArray(listOf("pqxdh-sync-v1", "dr-chacha-v1")))
        }.toString()
    }

    @Test fun validQrParses() {
        val r = PairingFormat.parse(validQr())
        assertTrue(r is PairingFormat.ParseResult.Ok)
        val b = (r as PairingFormat.ParseResult.Ok).bundle
        assertEquals("a".repeat(56) + ".onion", b.onionAddress)
        assertEquals("11".repeat(32), b.identityEd25519)
    }

    @Test fun fingerprintIsDeterministicAndGrouped() {
        val r = PairingFormat.parse(validQr()) as PairingFormat.ParseResult.Ok
        val fp1 = PairingFormat.fingerprint(r.bundle)
        val fp2 = PairingFormat.fingerprint(r.bundle)
        assertEquals(fp1, fp2)
        // 24 bytes -> 48 hex chars -> 12 groups of 4, space separated.
        assertEquals(12, fp1.split(" ").size)
        assertTrue(fp1.split(" ").all { it.length == 4 })
    }

    @Test fun fingerprintChangesWhenOnionChanges() {
        val r1 = PairingFormat.parse(validQr()) as PairingFormat.ParseResult.Ok
        val r2 = PairingFormat.parse(validQr().replace("a".repeat(56), "b".repeat(56)))
            as PairingFormat.ParseResult.Ok
        assertTrue(PairingFormat.fingerprint(r1.bundle) != PairingFormat.fingerprint(r2.bundle))
    }

    @Test fun rejectsNonJson() {
        assertTrue(PairingFormat.parse("hello world") is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsWrongProtocol() {
        val bad = validQr().replace("\"zt\"", "\"xx\"")
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsWrongVersion() {
        val bad = JSONObject(validQr()).apply { put("v", 2) }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsExpiredQr() {
        assertTrue(PairingFormat.parse(validQr(expiresInSeconds = -10))
            is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsExpiryTooFarInFuture() {
        assertTrue(PairingFormat.parse(validQr(expiresInSeconds = 3600))
            is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsBadOnion() {
        val bad = JSONObject(validQr()).apply { put("onion", "not-an-onion") }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsShortKey() {
        val bad = JSONObject(validQr()).apply { put("ik_ed", "11".repeat(16)) }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsNonHexKey() {
        val bad = JSONObject(validQr()).apply { put("ik_ed", "zz".repeat(32)) }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsMissingCapability() {
        val bad = JSONObject(validQr()).apply {
            put("caps", org.json.JSONArray(listOf("dr-chacha-v1")))
        }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsOversizedQr() {
        assertTrue(PairingFormat.parse("x".repeat(PairingFormat.MAX_QR_BYTES + 1))
            is PairingFormat.ParseResult.Invalid)
    }

    @Test fun rejectsMissingSignature() {
        val bad = JSONObject(validQr()).apply { remove("sig_ed") }.toString()
        assertTrue(PairingFormat.parse(bad) is PairingFormat.ParseResult.Invalid)
    }
}
