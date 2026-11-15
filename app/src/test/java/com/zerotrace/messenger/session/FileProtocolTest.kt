package com.zerotrace.messenger.session

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FileProtocolTest {

    @Test
    fun `text frame roundtrip with msg id`() {
        val encoded = WireFrame.encodeText(12345L, "hello 👋")
        val frame = WireFrame.decode(encoded)
        assertTrue(frame is WireFrame.Frame.Text)
        val text = frame as WireFrame.Frame.Text
        assertEquals(12345L, text.msgId)
        assertEquals("hello 👋", text.text)
    }

    @Test
    fun `legacy bare utf8 is accepted as text`() {
        val frame = WireFrame.decode("plain old text".toByteArray(Charsets.UTF_8))
        assertTrue(frame is WireFrame.Frame.Text)
        assertEquals("plain old text", (frame as WireFrame.Frame.Text).text)
        assertEquals(0L, frame.msgId)
    }

    @Test
    fun `malformed frames are dropped`() {
        assertNull(WireFrame.decode(byteArrayOf()))
        assertNull(WireFrame.decode(byteArrayOf(0x01))) // text header only
        assertNull(WireFrame.decode(byteArrayOf(0x03, 0x00))) // chunk header only
        assertNull(WireFrame.decode(byteArrayOf(0x02, '{'.code.toByte(), 'x'.code.toByte()))) // bad offer JSON
    }

    @Test
    fun `oversize file offer is rejected`() {
        val encoded = WireFrame.encodeOffer(1L, "big.bin", WireFrame.MAX_FILE_BYTES + 1, "00".repeat(32), "application/octet-stream", "file")
        assertNull(WireFrame.decode(encoded))
    }

    @Test
    fun `file offer chunk done roundtrip with integrity`() {
        val bytes = "hello file world".toByteArray(Charsets.UTF_8)
        val sha = WireFrame.sha256Hex(bytes)
        val offer = WireFrame.decode(WireFrame.encodeOffer(77L, "a.txt", bytes.size.toLong(), sha, "text/plain", "file")) as WireFrame.Frame.FileOffer
        assertEquals(77L, offer.fileId)
        assertEquals("a.txt", offer.name)
        val transfer = IncomingTransfer(offer)
        val chunk = WireFrame.decode(WireFrame.encodeChunk(77L, 0, bytes)) as WireFrame.Frame.FileChunk
        assertTrue(transfer.addChunk(chunk.index, chunk.bytes))
        assertTrue(transfer.complete)
        val done = WireFrame.decode(WireFrame.encodeDone(77L, sha)) as WireFrame.Frame.FileDone
        assertEquals(sha, done.sha256Hex)
        assertNotNull(transfer.assemble())
        assertEquals("hello file world", String(transfer.assemble()!!, Charsets.UTF_8))
    }

    @Test
    fun `tampered file bytes fail integrity`() {
        val bytes = "original".toByteArray(Charsets.UTF_8)
        val sha = WireFrame.sha256Hex(bytes)
        val offer = WireFrame.Frame.FileOffer(5L, "x.txt", bytes.size.toLong(), sha, "text/plain", "file")
        val transfer = IncomingTransfer(offer)
        val tampered = "tampered".toByteArray(Charsets.UTF_8)
        assertTrue(transfer.addChunk(0, tampered))
        assertNull(transfer.assemble())
    }

    @Test
    fun `duplicate and out-of-range chunks rejected`() {
        val bytes = ByteArray(40_000) { it.toByte() }
        val sha = WireFrame.sha256Hex(bytes)
        val offer = WireFrame.Frame.FileOffer(9L, "b.bin", bytes.size.toLong(), sha, "application/octet-stream", "file")
        val transfer = IncomingTransfer(offer)
        val c0 = bytes.copyOfRange(0, WireFrame.CHUNK_BYTES)
        val c1 = bytes.copyOfRange(WireFrame.CHUNK_BYTES, 32768)
        val c2 = bytes.copyOfRange(32768, 40000)
        assertTrue(transfer.addChunk(0, c0))
        assertFalse(transfer.addChunk(0, c0)) // duplicate
        assertFalse(transfer.addChunk(99, c1)) // out of range
        assertFalse(transfer.addChunk(1, ByteArray(WireFrame.CHUNK_BYTES + 1))) // oversize chunk
        assertTrue(transfer.addChunk(1, c1))
        assertTrue(transfer.addChunk(2, c2))
        assertTrue(transfer.complete)
        assertNotNull(transfer.assemble())
    }

    @Test
    fun `ack and reaction frames roundtrip`() {
        val ack = WireFrame.decode(WireFrame.encodeAck(true, 42L)) as WireFrame.Frame.Ack
        assertTrue(ack.delivered)
        assertEquals(42L, ack.msgId)
        val read = WireFrame.decode(WireFrame.encodeAck(false, 43L)) as WireFrame.Frame.Ack
        assertFalse(read.delivered)
        val react = WireFrame.decode(WireFrame.encodeReaction(42L, "❤️")) as WireFrame.Frame.Reaction
        assertEquals(42L, react.targetId)
        assertEquals("❤️", react.emoji)
        val accept = WireFrame.decode(WireFrame.encodeFileResponse(true, 7L)) as WireFrame.Frame.FileResponse
        assertTrue(accept.accepted)
        val decline = WireFrame.decode(WireFrame.encodeFileResponse(false, 7L)) as WireFrame.Frame.FileResponse
        assertFalse(decline.accepted)
    }

    @Test
    fun `status frame roundtrip`() {
        val encoded = WireFrame.encodeStatus("feeling good", null)
        val frame = WireFrame.decode(encoded) as WireFrame.Frame.Status
        assertEquals("feeling good", frame.text)
        assertNull(frame.imageBytes)
    }

    @Test
    fun `mime allowlist`() {
        assertTrue(WireFrame.mimeAllowed("image/jpeg"))
        assertTrue(WireFrame.mimeAllowed("video/mp4"))
        assertTrue(WireFrame.mimeAllowed("audio/mpeg"))
        assertTrue(WireFrame.mimeAllowed("application/pdf"))
        assertFalse(WireFrame.mimeAllowed("application/octet-stream"))
        assertFalse(WireFrame.mimeAllowed("application/x-executable"))
        assertFalse(WireFrame.mimeAllowed(null))
    }

    @Test
    fun `file name sanitization strips paths`() {
        assertEquals("evil.txt", WireFrame.sanitizeFileName("../../evil.txt"))
        assertEquals("a.txt", WireFrame.sanitizeFileName("C:\\Users\\x\\a.txt"))
        assertEquals("file", WireFrame.sanitizeFileName("///"))
    }

    @Test
    fun `sha256 is deterministic`() {
        val a = WireFrame.sha256Hex("abc".toByteArray())
        val b = WireFrame.sha256Hex("abc".toByteArray())
        assertEquals(a, b)
        assertEquals(64, a.length)
    }

    // ---- Call signaling (v0.3.0) ----

    private fun sampleCallId() = ByteArray(16) { it.toByte() }
    private fun sampleKey() = ByteArray(32) { (it * 3).toByte() }

    @Test
    fun `call invite roundtrip`() {
        val frame = WireFrame.decode(WireFrame.encodeCallInvite(sampleCallId(), sampleKey()))
        assertTrue(frame is WireFrame.Frame.CallInvite)
        val invite = frame as WireFrame.Frame.CallInvite
        assertEquals("000102030405060708090a0b0c0d0e0f", invite.callIdHex)
        val keyBytes = java.util.Base64.getDecoder().decode(invite.mediaKeyB64)
        assertArrayEquals(sampleKey(), keyBytes)
    }

    @Test
    fun `call response and end roundtrip`() {
        val hex = "000102030405060708090a0b0c0d0e0f"
        val accept = WireFrame.decode(WireFrame.encodeCallResponse(true, hex))
        assertTrue(accept is WireFrame.Frame.CallResponse)
        assertTrue((accept as WireFrame.Frame.CallResponse).accepted)
        assertEquals(hex, accept.callIdHex)
        val decline = WireFrame.decode(WireFrame.encodeCallResponse(false, hex))
        assertFalse((decline as WireFrame.Frame.CallResponse).accepted)
        val end = WireFrame.decode(WireFrame.encodeCallEnd(hex))
        assertTrue(end is WireFrame.Frame.CallEnd)
        assertEquals(hex, (end as WireFrame.Frame.CallEnd).callIdHex)
    }

    @Test
    fun `malformed call frames are dropped`() {
        // Bad callId hex (too short).
        val badId = WireFrame.encodeCallResponse(true, "abcd")
        assertNull(WireFrame.decode(badId))
        // Invite with a 16-byte key instead of 32.
        val badKey = run {
            val json = org.json.JSONObject().apply {
                put("id", "000102030405060708090a0b0c0d0e0f")
                put("key", java.util.Base64.getEncoder().encodeToString(ByteArray(16)))
            }.toString().toByteArray(Charsets.UTF_8)
            ByteArray(1 + json.size).also { it[0] = WireFrame.CALL_INVITE; json.copyInto(it, 1) }
        }
        assertNull(WireFrame.decode(badKey))
        // Invite with non-hex callId.
        val badHex = run {
            val json = org.json.JSONObject().apply {
                put("id", "zzzz02030405060708090a0b0c0d0e0f")
                put("key", java.util.Base64.getEncoder().encodeToString(sampleKey()))
            }.toString().toByteArray(Charsets.UTF_8)
            ByteArray(1 + json.size).also { it[0] = WireFrame.CALL_INVITE; json.copyInto(it, 1) }
        }
        assertNull(WireFrame.decode(badHex))
    }

    @Test
    fun `call id hex validation`() {
        assertTrue(WireFrame.validCallIdHex("000102030405060708090a0b0c0d0e0f"))
        assertFalse(WireFrame.validCallIdHex("000102030405060708090a0b0c0d0e0")) // 31 chars
        assertFalse(WireFrame.validCallIdHex("000102030405060708090A0B0C0D0E0F")) // uppercase
        assertArrayEquals(sampleCallId(), WireFrame.callIdHexToBytes("000102030405060708090a0b0c0d0e0f"))
        assertNull(WireFrame.callIdHexToBytes("xyz"))
    }
}
