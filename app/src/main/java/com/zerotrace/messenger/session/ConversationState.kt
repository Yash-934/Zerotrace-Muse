package com.zerotrace.messenger.session

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import com.zerotrace.messenger.data.Contact

enum class MessageKind { TEXT, IMAGE, FILE, AUDIO, VOICE_NOTE }

enum class MsgStatus { SENDING, SENT, DELIVERED, READ, RECEIVED, FAILED }

/**
 * One chat message. Payload bytes (images, files, voice notes) live ONLY in
 * [fileBytes] in RAM. Nothing in this class is ever written to disk, a
 * database, or a log. [msgId] is the wire id shared with the peer (text
 * frames and file ids); 0 means local-only (never sent).
 */
data class ChatMessage(
    val id: Long,
    val msgId: Long = 0L,
    val kind: MessageKind = MessageKind.TEXT,
    val text: String = "",
    val fileName: String? = null,
    val fileSize: Long = 0L,
    val fileBytes: ByteArray? = null,
    val mimeType: String? = null,
    val outgoing: Boolean,
    val status: MsgStatus = MsgStatus.RECEIVED,
    val replyToId: Long? = null,
    val reactions: Map<String, Int> = emptyMap(),
    val timestampMs: Long = System.currentTimeMillis()
) {
    /** Short preview for the chat list. Never used in notifications or widgets. */
    val preview: String
        get() = when (kind) {
            MessageKind.TEXT -> text
            MessageKind.IMAGE -> "📷 Photo"
            MessageKind.FILE -> "📎 ${fileName ?: "File"}"
            MessageKind.AUDIO -> "🎵 Audio"
            MessageKind.VOICE_NOTE -> "🎙 Voice note"
        }
}

/** A live-only status update from a peer. Cleared the moment the session ends. */
data class PeerStatus(
    val text: String,
    val imageBytes: ByteArray? = null,
    val timestampMs: Long = System.currentTimeMillis()
)

/** One call attempt. Only real attempts are recorded; there is no fake history. */
enum class CallDirection { INCOMING, OUTGOING, MISSED }
enum class CallKind { VOICE, VIDEO }

data class CallRecord(
    val id: Long,
    val contactOnion: String,
    val displayName: String,
    val direction: CallDirection,
    val kind: CallKind,
    val timestampMs: Long = System.currentTimeMillis(),
    /** Real outcome: "connected" (with durationSeconds), "missed", "declined", "failed". */
    val outcome: String = "failed",
    val durationSeconds: Long = 0L
)

/**
 * The live call state machine. Every state is real: the phone only "rings"
 * on a genuine invite, the timer only runs while media flows, and any
 * failure lands in [Ended] with the reason shown. See
 * `docs/CALLING_PHASE1.md` §7.
 */
sealed class CallUiState {
    data object Idle : CallUiState()
    data class Outgoing(val contact: Contact, val callIdHex: String, val startedMs: Long = System.currentTimeMillis()) : CallUiState()
    data class Incoming(val contact: Contact, val callIdHex: String, val receivedMs: Long = System.currentTimeMillis()) : CallUiState()
    data class Connecting(val contact: Contact, val callIdHex: String) : CallUiState()
    data class InCall(val contact: Contact, val callIdHex: String, val startedMs: Long, val muted: Boolean = false, val speaker: Boolean = false) : CallUiState()
    data class Ended(val contact: Contact?, val reason: String, val endedMs: Long = System.currentTimeMillis()) : CallUiState()
}

/**
 * Per-contact conversation state. Everything here is RAM-only: messages,
 * unread, mute, pin, peer status and the session handle all die with the
 * process (and messages die with the session — STRICT EPHEMERAL MODE).
 */
class Conversation(contact: Contact) {
    var contact by mutableStateOf(contact)
    val messages: SnapshotStateList<ChatMessage> = mutableStateListOf()
    var unread by mutableStateOf(0)
    var muted by mutableStateOf(false)
    var pinned by mutableStateOf(false)
    var blocked by mutableStateOf(false)
    var peerStatus by mutableStateOf<PeerStatus?>(null)
    var sessionHandle by mutableStateOf(0L)
    var lastActivityMs by mutableStateOf(0L)

    val hasLiveSession: Boolean get() = sessionHandle != 0L
    val lastMessage: ChatMessage? get() = messages.lastOrNull()
    val lastTimeMs: Long get() = lastMessage?.timestampMs ?: contact.addedEpochSeconds * 1000
}
