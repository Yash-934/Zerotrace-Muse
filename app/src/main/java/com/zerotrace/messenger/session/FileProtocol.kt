package com.zerotrace.messenger.session

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Base64

/**
 * Wire framing on top of the ratchet channel. The ratchet (Double Ratchet +
 * per-step ML-KEM, ChaCha20-Poly1305) still provides ALL encryption and
 * authentication; this layer only multiplexes message kinds inside the
 * already-encrypted plaintext. No cryptographic change, no new protocol.
 *
 * Layout: [type:1][payload]. Text frames carry a shared 8-byte message id so
 * the peer can honestly acknowledge delivery/read and reactions can target
 * them. File frames carry a shared 8-byte file id.
 *
 * Legacy bare UTF-8 (v1) is accepted as text with msgId 0 — v1 was never a
 * released peer, this is only defence-in-depth.
 */
object WireFrame {
    const val TEXT: Byte = 0x01
    const val FILE_OFFER: Byte = 0x02
    const val FILE_CHUNK: Byte = 0x03
    const val FILE_DONE: Byte = 0x04
    const val STATUS: Byte = 0x05
    const val ACK_DELIVERED: Byte = 0x06
    const val ACK_READ: Byte = 0x07
    const val REACTION: Byte = 0x08
    const val FILE_ACCEPT: Byte = 0x09
    const val FILE_DECLINE: Byte = 0x0A
    /** Call signaling (v0.3.0, Tor-native voice — see docs/CALLING_PHASE1.md). */
    const val CALL_INVITE: Byte = 0x0B
    const val CALL_ACCEPT: Byte = 0x0C
    const val CALL_DECLINE: Byte = 0x0D
    const val CALL_END: Byte = 0x0E

    const val MAX_FILE_BYTES: Long = 10L * 1024 * 1024
    const val CHUNK_BYTES: Int = 16 * 1024
    const val MAX_STATUS_IMAGE_BYTES: Int = 512 * 1024
    const val MAX_TEXT_BYTES: Int = 64 * 1024

    /** MIME types we accept for attachments. Anything else is refused at send and at receive. */
    val ALLOWED_MIME_PREFIXES = listOf("image/", "video/", "audio/", "text/")
    val ALLOWED_MIME_EXACT = setOf(
        "application/pdf", "application/zip",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )

    fun mimeAllowed(mime: String?): Boolean {
        if (mime == null) return false
        return ALLOWED_MIME_PREFIXES.any { mime.startsWith(it) } || mime in ALLOWED_MIME_EXACT
    }

    /** File names are display-only: strip every path separator and control char. */
    fun sanitizeFileName(name: String): String {
        val base = name.substringAfterLast('/').substringAfterLast('\\')
        val clean = base.filter { it.code >= 0x20 && it != ':' && it != '*' && it != '?' && it != '"' && it != '<' && it != '>' && it != '|' }
        return clean.take(120).ifEmpty { "file" }
    }

    fun sha256Hex(bytes: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(bytes)
        return d.joinToString("") { "%02x".format(it) }
    }

    sealed class Frame {
        data class Text(val msgId: Long, val text: String) : Frame()
        data class FileOffer(val fileId: Long, val name: String, val size: Long, val sha256Hex: String, val mime: String, val kind: String) : Frame()
        data class FileChunk(val fileId: Long, val index: Int, val bytes: ByteArray) : Frame()
        data class FileDone(val fileId: Long, val sha256Hex: String) : Frame()
        data class Status(val text: String, val imageBytes: ByteArray?) : Frame()
        data class Ack(val delivered: Boolean, val msgId: Long) : Frame()
        data class Reaction(val targetId: Long, val emoji: String) : Frame()
        data class FileResponse(val accepted: Boolean, val fileId: Long) : Frame()
        /** Call invite: one-time callId (hex, 16 B) + fresh media key (base64, 32 B). */
        data class CallInvite(val callIdHex: String, val mediaKeyB64: String) : Frame()
        /** Call accept/decline for one callId. */
        data class CallResponse(val accepted: Boolean, val callIdHex: String) : Frame()
        data class CallEnd(val callIdHex: String) : Frame()
    }

    fun encodeText(msgId: Long, text: String): ByteArray {
        val body = text.toByteArray(Charsets.UTF_8)
        require(body.size <= MAX_TEXT_BYTES) { "text too long" }
        return ByteBuffer.allocate(1 + 8 + body.size).order(ByteOrder.BIG_ENDIAN)
            .put(TEXT).putLong(msgId).put(body).array()
    }

    fun encodeOffer(fileId: Long, name: String, size: Long, sha256Hex: String, mime: String, kind: String): ByteArray {
        val json = JSONObject().apply {
            put("id", fileId); put("name", sanitizeFileName(name)); put("size", size)
            put("sha", sha256Hex); put("mime", mime); put("kind", kind)
            put("chunks", ((size + CHUNK_BYTES - 1) / CHUNK_BYTES).toInt())
        }.toString()
        val body = json.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + body.size).put(FILE_OFFER).put(body).array()
    }

    fun encodeChunk(fileId: Long, index: Int, bytes: ByteArray): ByteArray =
        ByteBuffer.allocate(1 + 8 + 4 + bytes.size).order(ByteOrder.BIG_ENDIAN)
            .put(FILE_CHUNK).putLong(fileId).putInt(index).put(bytes).array()

    fun encodeDone(fileId: Long, sha256Hex: String): ByteArray {
        val body = sha256Hex.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + 8 + body.size).order(ByteOrder.BIG_ENDIAN)
            .put(FILE_DONE).putLong(fileId).put(body).array()
    }

    fun encodeStatus(text: String, imageBytes: ByteArray?): ByteArray {
        val json = JSONObject().apply {
            put("t", text)
            if (imageBytes != null) put("img", Base64.getEncoder().encodeToString(imageBytes))
        }.toString()
        return ByteBuffer.allocate(1 + json.toByteArray(Charsets.UTF_8).size)
            .put(STATUS).put(json.toByteArray(Charsets.UTF_8)).array()
    }

    fun encodeAck(delivered: Boolean, msgId: Long): ByteArray =
        ByteBuffer.allocate(1 + 8).order(ByteOrder.BIG_ENDIAN)
            .put(if (delivered) ACK_DELIVERED else ACK_READ).putLong(msgId).array()

    fun encodeReaction(targetId: Long, emoji: String): ByteArray {
        val body = emoji.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + 8 + body.size).order(ByteOrder.BIG_ENDIAN)
            .put(REACTION).putLong(targetId).put(body).array()
    }

    fun encodeFileResponse(accepted: Boolean, fileId: Long): ByteArray =
        ByteBuffer.allocate(1 + 8).order(ByteOrder.BIG_ENDIAN)
            .put(if (accepted) FILE_ACCEPT else FILE_DECLINE).putLong(fileId).array()

    /** Call invite: callId as lowercase hex, media key as base64. */
    fun encodeCallInvite(callId: ByteArray, mediaKey: ByteArray): ByteArray {
        require(callId.size == 16) { "callId must be 16 bytes" }
        require(mediaKey.size == 32) { "media key must be 32 bytes" }
        val json = JSONObject().apply {
            put("id", callId.joinToString("") { "%02x".format(it) })
            put("key", Base64.getEncoder().encodeToString(mediaKey))
            put("caps", org.json.JSONArray().put("opus"))
            put("audio", true)
        }.toString()
        val body = json.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + body.size).put(CALL_INVITE).put(body).array()
    }

    fun encodeCallResponse(accepted: Boolean, callIdHex: String): ByteArray {
        val json = JSONObject().apply { put("id", callIdHex) }.toString()
        val body = json.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + body.size)
            .put(if (accepted) CALL_ACCEPT else CALL_DECLINE).put(body).array()
    }

    fun encodeCallEnd(callIdHex: String): ByteArray {
        val json = JSONObject().apply { put("id", callIdHex) }.toString()
        val body = json.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(1 + body.size).put(CALL_END).put(body).array()
    }

    /** A callId is exactly 16 bytes rendered as 32 lowercase hex chars. */
    fun validCallIdHex(hex: String): Boolean =
        hex.length == 32 && hex.all { it in '0'..'9' || it in 'a'..'f' }

    fun callIdHexToBytes(hex: String): ByteArray? {
        if (!validCallIdHex(hex)) return null
        return try {
            ByteArray(16) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        } catch (e: Exception) {
            null
        }
    }

    /** Returns null for malformed frames — the caller drops them, never crashes. */
    fun decode(data: ByteArray): Frame? {
        if (data.isEmpty()) return null
        return try {
            when (data[0]) {
                TEXT -> {
                    if (data.size < 9) null
                    else Frame.Text(
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long,
                        String(data, 9, data.size - 9, Charsets.UTF_8)
                    )
                }
                FILE_OFFER -> {
                    val o = JSONObject(String(data, 1, data.size - 1, Charsets.UTF_8))
                    val size = o.getLong("size")
                    if (size < 0 || size > MAX_FILE_BYTES) null
                    else Frame.FileOffer(
                        o.getLong("id"), sanitizeFileName(o.getString("name")), size,
                        o.getString("sha"), o.getString("mime"), o.optString("kind", "file")
                    )
                }
                FILE_CHUNK -> {
                    if (data.size < 13) null
                    else Frame.FileChunk(
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long,
                        ByteBuffer.wrap(data, 9, 4).order(ByteOrder.BIG_ENDIAN).int,
                        data.copyOfRange(13, data.size)
                    )
                }
                FILE_DONE -> {
                    if (data.size < 9) null
                    else Frame.FileDone(
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long,
                        String(data, 9, data.size - 9, Charsets.UTF_8)
                    )
                }
                STATUS -> {
                    val o = JSONObject(String(data, 1, data.size - 1, Charsets.UTF_8))
                    val img = (o.opt("img") as? String)?.let {
                        runCatching { Base64.getDecoder().decode(it) }.getOrNull()
                            ?.takeIf { b -> b.size <= MAX_STATUS_IMAGE_BYTES }
                    }
                    Frame.Status(o.optString("t", ""), img)
                }
                ACK_DELIVERED, ACK_READ -> {
                    if (data.size != 9) null
                    else Frame.Ack(
                        data[0] == ACK_DELIVERED,
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long
                    )
                }
                REACTION -> {
                    if (data.size < 9) null
                    else Frame.Reaction(
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long,
                        String(data, 9, data.size - 9, Charsets.UTF_8)
                    )
                }
                FILE_ACCEPT, FILE_DECLINE -> {
                    if (data.size != 9) null
                    else Frame.FileResponse(
                        data[0] == FILE_ACCEPT,
                        ByteBuffer.wrap(data, 1, 8).order(ByteOrder.BIG_ENDIAN).long
                    )
                }
                CALL_INVITE -> {
                    val o = JSONObject(String(data, 1, data.size - 1, Charsets.UTF_8))
                    val id = o.optString("id", "")
                    val key = o.optString("key", "")
                    if (!validCallIdHex(id)) null
                    else {
                        val keyBytes = runCatching { Base64.getDecoder().decode(key) }.getOrNull()
                        if (keyBytes == null || keyBytes.size != 32) null
                        else Frame.CallInvite(id, key)
                    }
                }
                CALL_ACCEPT, CALL_DECLINE -> {
                    val o = JSONObject(String(data, 1, data.size - 1, Charsets.UTF_8))
                    val id = o.optString("id", "")
                    if (!validCallIdHex(id)) null
                    else Frame.CallResponse(data[0] == CALL_ACCEPT, id)
                }
                CALL_END -> {
                    val o = JSONObject(String(data, 1, data.size - 1, Charsets.UTF_8))
                    val id = o.optString("id", "")
                    if (!validCallIdHex(id)) null else Frame.CallEnd(id)
                }
                else -> {
                    // Legacy v1: bare UTF-8 text with no type byte.
                    Frame.Text(0L, String(data, Charsets.UTF_8))
                }
            }
        } catch (e: Exception) {
            null
        }
    }
}

/** In-RAM reassembly of one incoming file transfer. No disk, no temp files. */
class IncomingTransfer(val offer: WireFrame.Frame.FileOffer) {
    private val chunks = HashMap<Int, ByteArray>()
    var receivedBytes: Long by mutableStateOf(0L)
        private set
    val totalChunks: Int get() = ((offer.size + WireFrame.CHUNK_BYTES - 1) / WireFrame.CHUNK_BYTES).toInt()
    val complete: Boolean get() = chunks.size == totalChunks && receivedBytes == offer.size

    /** Returns false for a bad index, oversize chunk, or duplicate chunk. */
    fun addChunk(index: Int, bytes: ByteArray): Boolean {
        if (index < 0 || index >= totalChunks) return false
        if (bytes.size > WireFrame.CHUNK_BYTES) return false
        if (chunks.containsKey(index)) return false
        chunks[index] = bytes
        receivedBytes += bytes.size
        return receivedBytes <= offer.size
    }

    /** Assembles and verifies SHA-256. Returns null on any mismatch. */
    fun assemble(): ByteArray? {
        if (!complete) return null
        val out = ByteArray(offer.size.toInt())
        var pos = 0
        for (i in 0 until totalChunks) {
            val c = chunks[i] ?: return null
            c.copyInto(out, pos)
            pos += c.size
        }
        return if (WireFrame.sha256Hex(out) == offer.sha256Hex) out else null
    }
}
