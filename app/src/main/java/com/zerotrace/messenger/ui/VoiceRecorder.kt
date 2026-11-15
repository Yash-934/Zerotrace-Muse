package com.zerotrace.messenger.ui

import android.media.MediaRecorder
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.FileInputStream

/**
 * Voice notes, recorded straight into RAM through a pipe FileDescriptor.
 * No plaintext audio file is ever written to disk. If the device refuses the
 * pipe, recording fails honestly — there is deliberately no temp-file fallback.
 */
class VoiceRecorder {
    private var recorder: MediaRecorder? = null
    private var readPipe: ParcelFileDescriptor? = null
    private var writePipe: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private val out = ByteArrayOutputStream()
    var isRecording: Boolean = false
        private set

    fun start(): Boolean {
        if (isRecording) return false
        return try {
            val pipes = ParcelFileDescriptor.createPipe()
            readPipe = pipes[0]
            writePipe = pipes[1]
            out.reset()
            readerThread = Thread {
                try {
                    FileInputStream(readPipe?.fileDescriptor).use { input ->
                        val buf = ByteArray(8192)
                        var n: Int
                        while (input.read(buf).also { n = it } >= 0) {
                            if (n > 0) out.write(buf, 0, n)
                        }
                    }
                } catch (_: Exception) {
                    // Pipe closed (stop/cancel) — expected path.
                }
            }.also { it.start() }
            @Suppress("DEPRECATION")
            val rec = MediaRecorder().apply {
                setAudioSource(MediaRecorder.AudioSource.MIC)
                setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP)
                setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB)
                setOutputFile(writePipe?.fileDescriptor)
                prepare()
                start()
            }
            recorder = rec
            isRecording = true
            true
        } catch (e: Exception) {
            stopInternal()
            false
        }
    }

    /** Stops and returns the recorded bytes, or null if nothing was captured. */
    fun stop(): ByteArray? {
        if (!isRecording) return null
        return try {
            recorder?.stop()
            val bytes = finishPipes()
            isRecording = false
            if (bytes.isEmpty()) null else bytes
        } catch (e: Exception) {
            stopInternal()
            null
        }
    }

    fun cancel() {
        stopInternal()
    }

    private fun finishPipes(): ByteArray {
        runCatching { writePipe?.close() }
        readerThread?.join(2000)
        runCatching { readPipe?.close() }
        runCatching { recorder?.release() }
        recorder = null
        return out.toByteArray()
    }

    private fun stopInternal() {
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        runCatching { writePipe?.close() }
        runCatching { readPipe?.close() }
        readerThread?.interrupt()
        isRecording = false
    }
}
