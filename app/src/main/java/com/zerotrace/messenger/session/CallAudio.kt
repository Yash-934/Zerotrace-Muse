package com.zerotrace.messenger.session

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecList
import android.media.MediaFormat
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.NoiseSuppressor
import android.os.SystemClock
import java.nio.ByteBuffer
import java.util.ArrayDeque

/**
 * Voice-call audio engine (v0.3.0, Tor-native voice — see
 * `docs/CALLING_PHASE1.md` §6).
 *
 * Pipeline: AudioRecord (VOICE_COMMUNICATION, 48 kHz mono, 20 ms frames) ->
 * Opus encoder (MediaCodec) -> [sendOpus] (Rust: AEAD + Tor onion stream),
 * and [pollOpus] (Rust: decrypted Opus frames) -> Opus decoder -> AudioTrack
 * (STREAM_VOICE_CALL). All buffers are RAM-only; nothing is recorded to disk.
 *
 * Honesty rules: Opus support is checked at runtime via MediaCodecList — if
 * the device has no Opus encoder/decoder, [start] fails with a clear error
 * instead of silently falling back to another codec. Echo cancellation and
 * noise suppression are attached only if the device reports them available;
 * [enhancementsInfo] says so either way.
 */
class CallAudioEngine(private val context: Context) {

    companion object {
        const val SAMPLE_RATE = 48000
        const val FRAME_SAMPLES = 960 // 20 ms at 48 kHz
        const val FRAME_BYTES = FRAME_SAMPLES * 2 // PCM16 mono
        const val OPUS_BITRATE = 24_000
        const val MAX_JITTER_MS = 200L
        const val MAX_JITTER_FRAMES = 50
    }

    enum class OpusSupport { OK, NO_ENCODER, NO_DECODER }

    /** Runtime Opus capability check (MediaCodecList). No silent fallback. */
    fun checkOpusSupport(): OpusSupport {
        val list = MediaCodecList(MediaCodecList.REGULAR_CODECS)
        val format = MediaFormat().apply {
            setString(MediaFormat.KEY_MIME, MediaFormat.MIMETYPE_AUDIO_OPUS)
            setInteger(MediaFormat.KEY_SAMPLE_RATE, SAMPLE_RATE)
            setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1)
            setInteger(MediaFormat.KEY_BIT_RATE, OPUS_BITRATE)
        }
        if (list.findEncoderForFormat(format) == null) return OpusSupport.NO_ENCODER
        if (list.findDecoderForFormat(format) == null) return OpusSupport.NO_DECODER
        return OpusSupport.OK
    }

    /** Human-readable line for the call screen: what actually got attached. */
    var enhancementsInfo: String = "Audio: Opus 48 kHz mono"
        private set

    @Volatile var muted: Boolean = false
        private set

    @Volatile private var running = false
    private var captureThread: Thread? = null
    private var playbackThread: Thread? = null
    private var recorder: AudioRecord? = null
    private var player: AudioTrack? = null
    private var encoder: MediaCodec? = null
    private var decoder: MediaCodec? = null
    private var echoCanceler: AcousticEchoCanceler? = null
    private var noiseSuppressor: NoiseSuppressor? = null
    private var audioManager: AudioManager? = null

    private val jitter = ArrayDeque<Pair<Long, ByteArray>>()
    private val jitterLock = Any()

    fun setMuted(m: Boolean) { muted = m }

    fun setSpeaker(on: Boolean) {
        audioManager?.isSpeakerphoneOn = on
    }

    /**
     * Start capture + playback. [sendOpus] is called with each encoded Opus
     * frame (20 ms); [pollOpus] returns the next received Opus frame or null.
     * Any fatal setup failure is reported via [onError] and the engine stops.
     */
    fun start(sendOpus: (ByteArray) -> Boolean, pollOpus: () -> ByteArray?, onError: (String) -> Unit) {
        if (running) return
        try {
            when (val support = checkOpusSupport()) {
                OpusSupport.NO_ENCODER -> { onError("Opus encoder not available on this device."); return }
                OpusSupport.NO_DECODER -> { onError("Opus decoder not available on this device."); return }
                OpusSupport.OK -> {}
            }
            audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            audioManager?.mode = AudioManager.MODE_IN_COMMUNICATION

            val minRec = AudioRecord.getMinBufferSize(
                SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
            )
            recorder = AudioRecord(
                android.media.MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT, minRec * 4
            )
            val sessionId = recorder!!.audioSessionId
            val aecOn = runCatching {
                if (AcousticEchoCanceler.isAvailable()) {
                    echoCanceler = AcousticEchoCanceler.create(sessionId)?.also { it.enabled = true }
                    echoCanceler != null
                } else false
            }.getOrDefault(false)
            val nsOn = runCatching {
                if (NoiseSuppressor.isAvailable()) {
                    noiseSuppressor = NoiseSuppressor.create(sessionId)?.also { it.enabled = true }
                    noiseSuppressor != null
                } else false
            }.getOrDefault(false)
            enhancementsInfo = "Audio: Opus 48 kHz mono · Echo cancellation: ${if (aecOn) "on" else "unavailable"} · Noise suppression: ${if (nsOn) "on" else "unavailable"}"

            val encFormat = MediaFormat().apply {
                setString(MediaFormat.KEY_MIME, MediaFormat.MIMETYPE_AUDIO_OPUS)
                setInteger(MediaFormat.KEY_SAMPLE_RATE, SAMPLE_RATE)
                setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1)
                setInteger(MediaFormat.KEY_BIT_RATE, OPUS_BITRATE)
                setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, FRAME_BYTES)
            }
            encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).also {
                it.configure(encFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                it.start()
            }

            val minPlay = AudioTrack.getMinBufferSize(
                SAMPLE_RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT
            )
            player = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .build()
                )
                .setTransferMode(AudioTrack.MODE_STREAM)
                .setBufferSizeInBytes(minPlay * 4)
                .build()

            val decFormat = MediaFormat().apply {
                setString(MediaFormat.KEY_MIME, MediaFormat.MIMETYPE_AUDIO_OPUS)
                setInteger(MediaFormat.KEY_SAMPLE_RATE, SAMPLE_RATE)
                setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1)
                setByteBuffer("csd-0", opusHead())
            }
            decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).also {
                it.configure(decFormat, null, null, 0)
                it.start()
            }

            running = true
            recorder!!.startRecording()
            player!!.play()

            captureThread = Thread({ captureLoop(sendOpus, onError) }, "zt-call-capture").also { it.start() }
            playbackThread = Thread({ playbackLoop(pollOpus, onError) }, "zt-call-playback").also { it.start() }
        } catch (e: Exception) {
            stop()
            onError("Audio start failed: ${e.message}")
        }
    }

    /** Minimal OpusHead (19 bytes) for the decoder: 1 channel, 48 kHz. */
    private fun opusHead(): ByteBuffer {
        val b = ByteBuffer.allocate(19)
        b.put("OpusHead".toByteArray(Charsets.US_ASCII))
        b.put(1) // version
        b.put(1) // channel count
        b.putShort(0) // pre-skip
        b.putInt(SAMPLE_RATE)
        b.putShort(0) // output gain
        b.put(0) // channel mapping family
        b.flip()
        return b
    }

    private fun captureLoop(sendOpus: (ByteArray) -> Boolean, onError: (String) -> Unit) {
        val pcm = ByteArray(FRAME_BYTES)
        val info = MediaCodec.BufferInfo()
        var ptsUs = 0L
        try {
            while (running) {
                val read = recorder?.read(pcm, 0, FRAME_BYTES) ?: break
                if (read <= 0) continue
                if (muted) continue // keep draining the recorder, send nothing
                val enc = encoder ?: break
                val inIdx = enc.dequeueInputBuffer(10_000)
                if (inIdx < 0) continue
                val inBuf = enc.getInputBuffer(inIdx) ?: continue
                inBuf.clear()
                inBuf.put(pcm, 0, read)
                enc.queueInputBuffer(inIdx, 0, read, ptsUs, 0)
                ptsUs += 20_000
                var outIdx = enc.dequeueOutputBuffer(info, 0)
                while (outIdx >= 0) {
                    val outBuf = enc.getOutputBuffer(outIdx)
                    if (outBuf != null && info.size > 0) {
                        val opus = ByteArray(info.size)
                        outBuf.get(opus)
                        sendOpus(opus)
                    }
                    enc.releaseOutputBuffer(outIdx, false)
                    outIdx = enc.dequeueOutputBuffer(info, 0)
                }
            }
        } catch (e: Exception) {
            if (running) onError("Capture failed: ${e.message}")
        }
    }

    private fun playbackLoop(pollOpus: () -> ByteArray?, onError: (String) -> Unit) {
        try {
            while (running) {
                val opus = pollOpus()
                if (opus == null) {
                    Thread.sleep(5)
                    drainJitterToPlayer()
                    continue
                }
                // Jitter buffer: drop frames older than MAX_JITTER_MS, cap size.
                synchronized(jitterLock) {
                    jitter.addLast(SystemClock.elapsedRealtime() to opus)
                    while (jitter.size > MAX_JITTER_FRAMES) jitter.removeFirst()
                }
                drainJitterToPlayer()
            }
        } catch (e: Exception) {
            if (running) onError("Playback failed: ${e.message}")
        }
    }

    private fun drainJitterToPlayer() {
        val dec = decoder ?: return
        val track = player ?: return
        val info = MediaCodec.BufferInfo()
        val now = SystemClock.elapsedRealtime()
        while (true) {
            val opus = synchronized(jitterLock) {
                val first = jitter.peekFirst() ?: return
                if (now - first.first > MAX_JITTER_MS) {
                    jitter.removeFirst()
                    return@synchronized null // drop this stale frame, retry next iteration
                }
                jitter.removeFirst().second
            } ?: continue
            val inIdx = dec.dequeueInputBuffer(10_000)
            if (inIdx < 0) return
            val inBuf = dec.getInputBuffer(inIdx) ?: return
            inBuf.clear()
            inBuf.put(opus)
            dec.queueInputBuffer(inIdx, 0, opus.size, SystemClock.elapsedRealtimeNanos() / 1000, 0)
            var outIdx = dec.dequeueOutputBuffer(info, 0)
            while (outIdx >= 0) {
                val outBuf = dec.getOutputBuffer(outIdx)
                if (outBuf != null && info.size > 0) {
                    val pcm = ByteArray(info.size)
                    outBuf.get(pcm)
                    track.write(pcm, 0, pcm.size)
                }
                dec.releaseOutputBuffer(outIdx, false)
                outIdx = dec.dequeueOutputBuffer(info, 0)
            }
        }
    }

    fun stop() {
        running = false
        runCatching { recorder?.stop() }
        runCatching { player?.stop() }
        captureThread?.join(500)
        playbackThread?.join(500)
        captureThread = null
        playbackThread = null
        runCatching { encoder?.stop(); encoder?.release() }
        runCatching { decoder?.stop(); decoder?.release() }
        runCatching { recorder?.release() }
        runCatching { player?.release() }
        runCatching { echoCanceler?.release() }
        runCatching { noiseSuppressor?.release() }
        encoder = null
        decoder = null
        recorder = null
        player = null
        echoCanceler = null
        noiseSuppressor = null
        audioManager?.let {
            runCatching { it.mode = AudioManager.MODE_NORMAL }
            runCatching { it.isSpeakerphoneOn = false }
        }
        audioManager = null
        synchronized(jitterLock) { jitter.clear() }
    }
}
