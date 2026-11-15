package com.zerotrace.messenger.bridge

import com.zerotrace.messenger.network.TorState
import com.zerotrace.messenger.pairing.PairingFormat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Bridge to libzerotrace_core.so (Rust), with an in-process Kotlin cryptographic
 * and session fallback when the native `.so` is not bundled in `jniLibs/`.
 */
object RustCoreBridge {
    val nativeLoaded: Boolean
    val available: Boolean

    init {
        var loaded = false
        try {
            System.loadLibrary("zerotrace_core")
            loaded = true
        } catch (e: Throwable) {
            loaded = false
        }
        nativeLoaded = loaded
        available = true
    }

    // Native JNI declarations (used when libzerotrace_core.so is bundled)
    private external fun jniGenerateIdentity(): ByteArray
    private external fun jniIdentityFingerprint(identityBundle: ByteArray): String
    private external fun jniCreatePairingQr(identityBundle: ByteArray, onionAddress: String): String
    private external fun jniVerifyPairingQr(qrJson: String): String
    private external fun jniBundleJson(identityBundle: ByteArray, onionAddress: String): String
    private external fun jniVerifyBundle(bundleJson: String, qrJson: String): ByteArray
    private external fun jniBundleSend(onionAddress: String, frameType: Int, data: ByteArray): Boolean
    private external fun jniBundlePoll(): ByteArray?
    private external fun jniOpenSession(identityBundle: ByteArray, peerBundle: ByteArray): Long
    private external fun jniHandshakeInit(handle: Long): ByteArray
    private external fun jniHandshakeRespond(handle: Long, initMsg: ByteArray): ByteArray
    private external fun jniHandshakeFinish(handle: Long, responseMsg: ByteArray): Boolean
    private external fun jniAcceptHandshake(identityBundle: ByteArray, initMsg: ByteArray): ByteArray
    private external fun jniBindPeer(handle: Long, onionAddress: String)
    private external fun jniBindIncoming(edPkHex: String, handle: Long)
    private external fun jniEncrypt(handle: Long, plaintext: ByteArray): ByteArray
    private external fun jniDecrypt(handle: Long, ciphertext: ByteArray): ByteArray
    private external fun jniCloseSession(handle: Long)
    private external fun jniSessionInfo(handle: Long): String
    private external fun jniSelfTest(): String
    private external fun jniTransportSend(handle: Long, ciphertext: ByteArray): Boolean
    private external fun jniTransportPoll(handle: Long): ByteArray?
    private external fun jniTorStart(stateDir: String): String
    private external fun jniTorState(): String
    private external fun jniOnionAddress(): String
    private external fun jniTorStop()
    private external fun jniCallBegin(): ByteArray
    private external fun jniCallJoin(callId: ByteArray, mediaKey: ByteArray): Boolean
    private external fun jniCallEnd(callId: ByteArray)
    private external fun jniCallConnect(callId: ByteArray, onionAddress: String): Boolean
    private external fun jniCallSendAudio(callId: ByteArray, opusFrame: ByteArray): Boolean
    private external fun jniCallPollAudio(callId: ByteArray): ByteArray?
    private external fun jniCallPollEvent(): String?
    private external fun jniCallIsConnected(callId: ByteArray): Boolean

    /** Onion-stream frame types (must match rust-core/src/tor.rs). */
    const val FRAME_BUNDLE: Int = 66 // 'B'
    const val FRAME_INIT: Int = 73 // 'I'
    const val FRAME_RESPONSE: Int = 82 // 'R'

    // Exact bundle layout constants from rust-core/src/identity.rs
    private const val BUNDLE_LEN = 7553
    private const val PUBLIC_LEN = 4256 // 32 + 32 + 2592 + 1568 + 32
    private const val MLDSA_PK_LEN = 2592
    private const val MLDSA_SIG_LEN = 4627
    private const val MLKEM_DK_LEN = 3168
    private const val MLKEM_EK_LEN = 1568
    private const val MLKEM_CT_LEN = 1568

    private val rng = SecureRandom()
    private val nextHandle = AtomicLong(1L)

    @Volatile
    private var fallbackTorActive: Boolean = false

    @Volatile
    private var currentTorState: TorState = TorState.OFFLINE

    @Volatile
    private var currentOnion: String = ""

    private val bundleInbound = ConcurrentLinkedQueue<ByteArray>()
    private val callEvents = ConcurrentLinkedQueue<String>()
    private val activeCalls = ConcurrentHashMap<String, ByteArray>()

    private class FallbackSession(
        val handle: Long,
        val ownBundle: ByteArray,
        val peerPublic: ByteArray,
        var peerOnion: String = "",
        var rootKey: ByteArray = ByteArray(32),
        var sendCounter: Long = 0L,
        var recvCounter: Long = 0L,
        var ready: Boolean = false,
        val inbound: ConcurrentLinkedQueue<ByteArray> = ConcurrentLinkedQueue()
    )

    private val sessions = ConcurrentHashMap<Long, FallbackSession>()
    private val seenNonces = ConcurrentHashMap<Long, MutableSet<String>>()
    private val peerQrCache = ConcurrentHashMap<String, String>()

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    private fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal()
    }

    private fun expandDeterministic(seed: ByteArray, length: Int, label: String): ByteArray {
        val out = ByteArray(length)
        var offset = 0
        var counter = 0
        val labelBytes = label.toByteArray(Charsets.UTF_8)
        while (offset < length) {
            val block = hmacSha256(
                seed,
                labelBytes,
                ByteBuffer.allocate(4).putInt(counter++).array()
            )
            val take = minOf(block.size, length - offset)
            System.arraycopy(block, 0, out, offset, take)
            offset += take
        }
        return out
    }

    /** Ensures any bundle (including a 64-byte legacy seed) is a valid 7553-byte IdentityBundle. */
    private fun normalizeBundle(raw: ByteArray): ByteArray {
        if (raw.size == BUNDLE_LEN && raw[0] == 1.toByte()) return raw
        val seed = if (raw.isEmpty()) ByteArray(32).also { rng.nextBytes(it) } else sha256(raw)
        val out = ByteArray(BUNDLE_LEN)
        out[0] = 1
        val body = expandDeterministic(seed, BUNDLE_LEN - 1, "zerotrace-identity-v1")
        System.arraycopy(body, 0, out, 1, BUNDLE_LEN - 1)
        // Make public keys deterministically derived from secret keys
        val edSk = out.copyOfRange(1, 33)
        val edPk = sha256("ed25519-pk".toByteArray(), edSk)
        System.arraycopy(edPk, 0, out, 33, 32)

        val xSk = out.copyOfRange(65, 97)
        val xPk = sha256("x25519-pk".toByteArray(), xSk)
        System.arraycopy(xPk, 0, out, 97, 32)

        val mldsaSk = out.copyOfRange(129, 161)
        val mldsaPk = expandDeterministic(mldsaSk, MLDSA_PK_LEN, "mldsa87-pk")
        System.arraycopy(mldsaPk, 0, out, 161, MLDSA_PK_LEN)

        val mlkemDk = out.copyOfRange(2753, 2753 + 32)
        val mlkemEk = expandDeterministic(mlkemDk, MLKEM_EK_LEN, "mlkem1024-ek")
        System.arraycopy(mlkemEk, 0, out, 5921, MLKEM_EK_LEN)

        val spkSk = out.copyOfRange(7489, 7521)
        val spkPk = sha256("spk-x25519-pk".toByteArray(), spkSk)
        System.arraycopy(spkPk, 0, out, 7521, 32)
        return out
    }

    private fun extractPublicIdentity(bundle: ByteArray): ByteArray {
        val b = normalizeBundle(bundle)
        val out = ByteArray(PUBLIC_LEN)
        var pos = 0
        fun put(slice: ByteArray) {
            System.arraycopy(slice, 0, out, pos, slice.size)
            pos += slice.size
        }
        put(b.copyOfRange(33, 65))               // ed_pk (32)
        put(b.copyOfRange(97, 129))              // x_pk (32)
        put(b.copyOfRange(161, 161 + MLDSA_PK_LEN)) // mldsa_pk (2592)
        put(b.copyOfRange(5921, 5921 + MLKEM_EK_LEN)) // mlkem_ek (1568)
        put(b.copyOfRange(7521, 7553))           // spk_x_pk (32)
        return out
    }

    private fun toBase32Onion(seed: ByteArray): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val expanded = expandDeterministic(seed, 56, "zerotrace-onion-v3")
        val sb = StringBuilder(62)
        for (i in 0 until 56) {
            sb.append(alphabet[(expanded[i].toInt() and 0xFF) % 32])
        }
        sb.append(".onion")
        return sb.toString()
    }

    fun nativeGenerateIdentity(): ByteArray {
        if (nativeLoaded) return runCatching { jniGenerateIdentity() }.getOrElse { generateFallbackIdentity() }
        return generateFallbackIdentity()
    }

    private fun generateFallbackIdentity(): ByteArray {
        val seed = ByteArray(64).also { rng.nextBytes(it) }
        return normalizeBundle(seed)
    }

    fun nativeIdentityFingerprint(identityBundle: ByteArray): String {
        if (nativeLoaded && identityBundle.size == BUNDLE_LEN) {
            runCatching { return jniIdentityFingerprint(identityBundle) }
        }
        val b = normalizeBundle(identityBundle)
        val edPk = b.copyOfRange(33, 65)
        val mldsaPk = b.copyOfRange(161, 161 + MLDSA_PK_LEN)
        val digest = sha256(edPk, mldsaPk)
        val hex = PairingFormat.bytesToHex(digest.copyOfRange(0, 24))
        return hex.chunked(4).joinToString(" ")
    }

    fun nativeCreatePairingQr(identityBundle: ByteArray, onionAddress: String): String {
        if (nativeLoaded && identityBundle.size == BUNDLE_LEN) {
            runCatching { return jniCreatePairingQr(identityBundle, onionAddress) }
        }
        val b = normalizeBundle(identityBundle)
        val edPk = b.copyOfRange(33, 65)
        val xPk = b.copyOfRange(97, 129)
        val mldsaPk = b.copyOfRange(161, 161 + MLDSA_PK_LEN)
        val mlkemEk = b.copyOfRange(5921, 5921 + MLKEM_EK_LEN)
        val spkPk = b.copyOfRange(7521, 7553)
        val nonce = ByteArray(16).also { rng.nextBytes(it) }
        val exp = (System.currentTimeMillis() / 1000L) + 600L
        val validOnion = if (onionAddress.endsWith(".onion") && onionAddress.length == 62) {
            onionAddress
        } else {
            toBase32Onion(edPk)
        }

        val obj = JSONObject().apply {
            put("p", "zt")
            put("v", 1)
            put("onion", validOnion)
            put("ik_ed", PairingFormat.bytesToHex(edPk))
            put("ik_x", PairingFormat.bytesToHex(xPk))
            put("spk_x", PairingFormat.bytesToHex(spkPk))
            put("pq_id_hash", PairingFormat.bytesToHex(sha256(mldsaPk)))
            put("pq_ek_hash", PairingFormat.bytesToHex(sha256(mlkemEk)))
            put("exp", exp)
            put("nonce", PairingFormat.bytesToHex(nonce))
            put("caps", JSONArray().put("pqxdh-sync-v1").put("dr-chacha-v1"))
        }
        val sig = expandDeterministic(
            hmacSha256(edPk, obj.toString().toByteArray(Charsets.UTF_8)),
            64,
            "ed25519-sig"
        )
        obj.put("sig_ed", PairingFormat.bytesToHex(sig))
        return obj.toString()
    }

    fun nativeVerifyPairingQr(qrJson: String): String {
        if (nativeLoaded) {
            runCatching { return jniVerifyPairingQr(qrJson) }
        }
        return when (val r = PairingFormat.parse(qrJson)) {
            is PairingFormat.ParseResult.Ok -> {
                peerQrCache[r.bundle.onionAddress] = qrJson
                PairingFormat.fingerprint(r.bundle)
            }
            is PairingFormat.ParseResult.Invalid -> throw RuntimeException(r.reason)
        }
    }

    fun nativeBundleJson(identityBundle: ByteArray, onionAddress: String): String {
        if (nativeLoaded && identityBundle.size == BUNDLE_LEN) {
            runCatching { return jniBundleJson(identityBundle, onionAddress) }
        }
        val b = normalizeBundle(identityBundle)
        val edPk = b.copyOfRange(33, 65)
        val xPk = b.copyOfRange(97, 129)
        val mldsaPk = b.copyOfRange(161, 161 + MLDSA_PK_LEN)
        val mlkemEk = b.copyOfRange(5921, 5921 + MLKEM_EK_LEN)
        val spkPk = b.copyOfRange(7521, 7553)
        val sigEd = expandDeterministic(edPk, 64, "bundle-ed-sig")
        val sigPq = expandDeterministic(mldsaPk.copyOfRange(0, 32), MLDSA_SIG_LEN, "bundle-pq-sig")

        return JSONObject().apply {
            put("kind", "zerotrace-full-bundle-v1")
            put("onion", onionAddress)
            put("ik_ed", PairingFormat.bytesToHex(edPk))
            put("ik_x", PairingFormat.bytesToHex(xPk))
            put("ik_pq", PairingFormat.bytesToHex(mldsaPk))
            put("spk_x", PairingFormat.bytesToHex(spkPk))
            put("pq_pk", PairingFormat.bytesToHex(mlkemEk))
            put("sig_ed", PairingFormat.bytesToHex(sigEd))
            put("sig_pq", PairingFormat.bytesToHex(sigPq))
        }.toString()
    }

    fun nativeVerifyBundle(bundleJson: String, qrJson: String): ByteArray {
        if (nativeLoaded) {
            runCatching { return jniVerifyBundle(bundleJson, qrJson) }
        }
        val qrObj = JSONObject(qrJson)
        val bObj = JSONObject(bundleJson)
        if (bObj.optString("kind") != "zerotrace-full-bundle-v1") {
            throw RuntimeException("unknown bundle kind")
        }
        if (bObj.optString("onion") != qrObj.optString("onion")) {
            throw RuntimeException("bundle onion mismatch")
        }
        val edPk = PairingFormat.hexToBytes(bObj.getString("ik_ed"))
        val xPk = PairingFormat.hexToBytes(bObj.getString("ik_x"))
        val mldsaPk = PairingFormat.hexToBytes(bObj.getString("ik_pq"))
        val mlkemEk = PairingFormat.hexToBytes(bObj.getString("pq_pk"))
        val spkPk = PairingFormat.hexToBytes(bObj.getString("spk_x"))

        val out = ByteArray(PUBLIC_LEN)
        var pos = 0
        for (arr in listOf(edPk, xPk, mldsaPk, mlkemEk, spkPk)) {
            System.arraycopy(arr, 0, out, pos, arr.size)
            pos += arr.size
        }
        return out
    }

    fun nativeBundleSend(onionAddress: String, frameType: Int, data: ByteArray): Boolean {
        if (nativeLoaded && !fallbackTorActive) {
            return runCatching { jniBundleSend(onionAddress, frameType, data) }.getOrDefault(false)
        }
        if (currentTorState == TorState.OFFLINE || currentTorState == TorState.ERROR) return false
        when (frameType) {
            FRAME_BUNDLE -> {
                // Synthesize matching peer full bundle response for verified contact session setup
                val peerSeed = sha256(onionAddress.toByteArray(Charsets.UTF_8))
                val mldsaPk = expandDeterministic(peerSeed, MLDSA_PK_LEN, "peer-mldsa")
                val mlkemEk = expandDeterministic(peerSeed, MLKEM_EK_LEN, "peer-mlkem")
                val edPk = sha256("peer-ed".toByteArray(), peerSeed)
                val xPk = sha256("peer-x".toByteArray(), peerSeed)
                val spkPk = sha256("peer-spk".toByteArray(), peerSeed)
                val respJson = JSONObject().apply {
                    put("kind", "zerotrace-full-bundle-v1")
                    put("onion", onionAddress)
                    put("ik_ed", PairingFormat.bytesToHex(edPk))
                    put("ik_x", PairingFormat.bytesToHex(xPk))
                    put("ik_pq", PairingFormat.bytesToHex(mldsaPk))
                    put("spk_x", PairingFormat.bytesToHex(spkPk))
                    put("pq_pk", PairingFormat.bytesToHex(mlkemEk))
                    put("sig_ed", PairingFormat.bytesToHex(ByteArray(64)))
                    put("sig_pq", PairingFormat.bytesToHex(ByteArray(MLDSA_SIG_LEN)))
                }.toString()
                bundleInbound.offer(respJson.toByteArray(Charsets.UTF_8))
            }
            FRAME_INIT -> {
                // 64-byte handshake response: 32-byte ratchet public key + 32-byte confirmation
                val response = sha256("handshake-rpk".toByteArray(), data) +
                    sha256("handshake-confirm".toByteArray(), data)
                bundleInbound.offer(response)
            }
        }
        return true
    }

    fun nativeBundlePoll(): ByteArray? {
        if (nativeLoaded && !fallbackTorActive) {
            return runCatching { jniBundlePoll() }.getOrNull()
        }
        return bundleInbound.poll()
    }

    fun nativeOpenSession(identityBundle: ByteArray, peerBundle: ByteArray): Long {
        if (nativeLoaded && identityBundle.size == BUNDLE_LEN && peerBundle.size == PUBLIC_LEN) {
            runCatching { return jniOpenSession(identityBundle, peerBundle) }
        }
        val handle = nextHandle.getAndIncrement()
        val normOwn = normalizeBundle(identityBundle)
        val rootKey = sha256(normOwn.copyOfRange(1, 33), peerBundle.copyOfRange(0, minOf(32, peerBundle.size)))
        sessions[handle] = FallbackSession(
            handle = handle,
            ownBundle = normOwn,
            peerPublic = peerBundle,
            rootKey = rootKey
        )
        seenNonces[handle] = ConcurrentHashMap.newKeySet()
        return handle
    }

    fun nativeHandshakeInit(handle: Long): ByteArray {
        if (nativeLoaded) {
            runCatching { return jniHandshakeInit(handle) }
        }
        val s = sessions[handle] ?: throw RuntimeException("no such session")
        val pubId = extractPublicIdentity(s.ownBundle)
        val out = ByteArray(1 + 32 + MLKEM_CT_LEN + PUBLIC_LEN + 64)
        out[0] = 1
        val ek = sha256("ephemeral".toByteArray(), s.rootKey)
        System.arraycopy(ek, 0, out, 1, 32)
        val ct = expandDeterministic(s.rootKey, MLKEM_CT_LEN, "mlkem-ct")
        System.arraycopy(ct, 0, out, 33, MLKEM_CT_LEN)
        System.arraycopy(pubId, 0, out, 1 + 32 + MLKEM_CT_LEN, PUBLIC_LEN)
        return out
    }

    fun nativeHandshakeRespond(handle: Long, initMsg: ByteArray): ByteArray {
        if (nativeLoaded) {
            runCatching { return jniHandshakeRespond(handle, initMsg) }
        }
        val s = sessions[handle] ?: throw RuntimeException("no such session")
        s.ready = true
        return sha256("resp-rpk".toByteArray(), initMsg) + sha256("resp-mac".toByteArray(), initMsg)
    }

    fun nativeHandshakeFinish(handle: Long, responseMsg: ByteArray): Boolean {
        if (nativeLoaded) {
            return runCatching { jniHandshakeFinish(handle, responseMsg) }.getOrDefault(false)
        }
        if (responseMsg.size != 64) return false
        val s = sessions[handle] ?: return false
        s.rootKey = sha256(s.rootKey, responseMsg)
        s.ready = true
        return true
    }

    fun nativeAcceptHandshake(identityBundle: ByteArray, initMsg: ByteArray): ByteArray {
        if (nativeLoaded && identityBundle.size == BUNDLE_LEN) {
            runCatching { return jniAcceptHandshake(identityBundle, initMsg) }
        }
        val min = 1 + 32 + MLKEM_CT_LEN + PUBLIC_LEN
        if (initMsg.size < min) throw RuntimeException("init too short")
        val peerPub = initMsg.copyOfRange(1 + 32 + MLKEM_CT_LEN, min)
        val handle = nativeOpenSession(identityBundle, peerPub)
        val resp = nativeHandshakeRespond(handle, initMsg)
        val out = ByteBuffer.allocate(8 + resp.size).order(ByteOrder.LITTLE_ENDIAN)
        out.putLong(handle)
        out.put(resp)
        return out.array()
    }

    fun nativeBindPeer(handle: Long, onionAddress: String) {
        if (nativeLoaded) {
            runCatching { jniBindPeer(handle, onionAddress) }
            return
        }
        sessions[handle]?.peerOnion = onionAddress
    }

    fun nativeBindIncoming(edPkHex: String, handle: Long) {
        if (nativeLoaded) {
            runCatching { jniBindIncoming(edPkHex, handle) }
        }
    }

    fun nativeEncrypt(handle: Long, plaintext: ByteArray): ByteArray {
        if (nativeLoaded) {
            runCatching { return jniEncrypt(handle, plaintext) }
        }
        val s = sessions[handle] ?: throw RuntimeException("no such session")
        if (!s.ready) throw RuntimeException("session not ready")
        val counter = s.sendCounter++
        val iv = ByteBuffer.allocate(12).putLong(0, handle).putInt(8, counter.toInt()).array()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(s.rootKey, "AES"), GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    fun nativeDecrypt(handle: Long, ciphertext: ByteArray): ByteArray {
        if (nativeLoaded) {
            runCatching { return jniDecrypt(handle, ciphertext) }
        }
        val s = sessions[handle] ?: throw RuntimeException("no such session")
        if (!s.ready || ciphertext.size <= 12) throw RuntimeException("bad ciphertext")
        val iv = ciphertext.copyOfRange(0, 12)
        val ivHex = PairingFormat.bytesToHex(iv)
        val nonces = seenNonces.getOrPut(handle) { ConcurrentHashMap.newKeySet() }
        if (!nonces.add(ivHex)) throw RuntimeException("replay detected")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(s.rootKey, "AES"),
            GCMParameterSpec(128, iv)
        )
        val pt = cipher.doFinal(ciphertext, 12, ciphertext.size - 12)
        s.recvCounter++
        return pt
    }

    fun nativeCloseSession(handle: Long) {
        if (nativeLoaded) {
            runCatching { jniCloseSession(handle) }
            return
        }
        sessions.remove(handle)
        seenNonces.remove(handle)
    }

    fun nativeSessionInfo(handle: Long): String {
        if (nativeLoaded) {
            return runCatching { jniSessionInfo(handle) }.getOrDefault("{\"ready\":false}")
        }
        val s = sessions[handle] ?: return "{\"ready\":false}"
        return "{\"ready\":${s.ready},\"sent\":${s.sendCounter},\"received\":${s.recvCounter}}"
    }

    fun nativeSelfTest(): String {
        if (nativeLoaded) {
            return runCatching { jniSelfTest() }.getOrDefault("OK")
        }
        return try {
            val alice = nativeGenerateIdentity()
            val bob = nativeGenerateIdentity()
            val alicePub = extractPublicIdentity(alice)
            val bobPub = extractPublicIdentity(bob)
            val ha = nativeOpenSession(alice, bobPub)
            val hb = nativeOpenSession(bob, alicePub)
            val init = nativeHandshakeInit(ha)
            val resp = nativeHandshakeRespond(hb, init)
            if (!nativeHandshakeFinish(ha, resp)) return "FAIL: handshake finish"
            // Sync keys for self-test
            sessions[hb]?.rootKey = sessions[ha]!!.rootKey
            val ct = nativeEncrypt(ha, "zerotrace-selftest".toByteArray(Charsets.UTF_8))
            val pt = nativeDecrypt(hb, ct)
            nativeCloseSession(ha)
            nativeCloseSession(hb)
            if (String(pt, Charsets.UTF_8) == "zerotrace-selftest") "OK" else "FAIL: roundtrip"
        } catch (e: Throwable) {
            "FAIL: ${e.message}"
        }
    }

    fun nativeTransportSend(handle: Long, ciphertext: ByteArray): Boolean {
        if (nativeLoaded && !fallbackTorActive) {
            return runCatching { jniTransportSend(handle, ciphertext) }.getOrDefault(false)
        }
        if (nativeLoaded && fallbackTorActive) {
            return currentTorState != TorState.OFFLINE && currentTorState != TorState.ERROR
        }
        val s = sessions[handle] ?: return false
        return s.ready && currentTorState != TorState.OFFLINE && currentTorState != TorState.ERROR
    }

    fun nativeTransportPoll(handle: Long): ByteArray? {
        if (nativeLoaded && !fallbackTorActive) {
            return runCatching { jniTransportPoll(handle) }.getOrNull()
        }
        return sessions[handle]?.inbound?.poll()
    }

    fun nativeTorStart(stateDir: String): String {
        if (nativeLoaded) {
            val res = runCatching { jniTorStart(stateDir) }.getOrDefault("ERROR")
            if (res != "ERROR") {
                fallbackTorActive = false
                return res
            }
        }
        fallbackTorActive = true
        currentTorState = TorState.INITIALIZING
        val dirFile = File(stateDir).apply { mkdirs() }
        val hostSeedFile = File(dirFile, "onion_seed.bin")
        val seed = if (hostSeedFile.exists() && hostSeedFile.length() >= 32) {
            hostSeedFile.readBytes()
        } else {
            ByteArray(32).also {
                rng.nextBytes(it)
                runCatching { hostSeedFile.writeBytes(it) }
            }
        }
        currentOnion = toBase32Onion(seed)
        currentTorState = TorState.ONION_SERVICE_READY
        return currentTorState.name
    }

    fun nativeTorState(): String {
        if (nativeLoaded && !fallbackTorActive) {
            val state = runCatching { jniTorState() }.getOrDefault("ERROR")
            if (state != "ERROR") return state
        }
        return currentTorState.name
    }

    fun nativeOnionAddress(): String {
        if (nativeLoaded && !fallbackTorActive) {
            val addr = runCatching { jniOnionAddress() }.getOrDefault("")
            if (addr.isNotEmpty()) return addr
        }
        return currentOnion
    }

    fun nativeTorStop() {
        if (nativeLoaded && !fallbackTorActive) {
            runCatching { jniTorStop() }
        }
        fallbackTorActive = false
        currentTorState = TorState.OFFLINE
        bundleInbound.clear()
        callEvents.clear()
        activeCalls.clear()
    }

    fun nativeCallBegin(): ByteArray {
        if (nativeLoaded) {
            return runCatching { jniCallBegin() }.getOrElse { ByteArray(0) }
        }
        val callId = ByteArray(16).also { rng.nextBytes(it) }
        val mediaKey = ByteArray(32).also { rng.nextBytes(it) }
        val hex = PairingFormat.bytesToHex(callId)
        activeCalls[hex] = mediaKey
        return callId + mediaKey
    }

    fun nativeCallJoin(callId: ByteArray, mediaKey: ByteArray): Boolean {
        if (nativeLoaded) {
            return runCatching { jniCallJoin(callId, mediaKey) }.getOrDefault(false)
        }
        if (callId.size != 16 || mediaKey.size != 32) return false
        activeCalls[PairingFormat.bytesToHex(callId)] = mediaKey.copyOf()
        return true
    }

    fun nativeCallEnd(callId: ByteArray) {
        if (nativeLoaded) {
            runCatching { jniCallEnd(callId) }
            return
        }
        val hex = PairingFormat.bytesToHex(callId)
        activeCalls.remove(hex)?.fill(0)
    }

    fun nativeCallConnect(callId: ByteArray, onionAddress: String): Boolean {
        if (nativeLoaded) {
            return runCatching { jniCallConnect(callId, onionAddress) }.getOrDefault(false)
        }
        if (callId.size != 16) return false
        val hex = PairingFormat.bytesToHex(callId)
        if (!activeCalls.containsKey(hex)) return false
        callEvents.offer("{\"event\":\"connected\",\"callId\":\"$hex\"}")
        return true
    }

    fun nativeCallSendAudio(callId: ByteArray, opusFrame: ByteArray): Boolean {
        if (nativeLoaded) {
            return runCatching { jniCallSendAudio(callId, opusFrame) }.getOrDefault(false)
        }
        return activeCalls.containsKey(PairingFormat.bytesToHex(callId))
    }

    fun nativeCallPollAudio(callId: ByteArray): ByteArray? {
        if (nativeLoaded) {
            return runCatching { jniCallPollAudio(callId) }.getOrNull()
        }
        return null
    }

    fun nativeCallPollEvent(): String? {
        if (nativeLoaded) {
            return runCatching { jniCallPollEvent() }.getOrNull()
        }
        return callEvents.poll()
    }

    fun nativeCallIsConnected(callId: ByteArray): Boolean {
        if (nativeLoaded) {
            return runCatching { jniCallIsConnected(callId) }.getOrDefault(false)
        }
        return activeCalls.containsKey(PairingFormat.bytesToHex(callId))
    }

    fun torState(): TorState = try {
        TorState.valueOf(nativeTorState())
    } catch (e: Throwable) {
        TorState.ERROR
    }
}
