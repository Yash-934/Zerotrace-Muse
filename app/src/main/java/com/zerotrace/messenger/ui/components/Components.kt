package com.zerotrace.messenger.ui.components

import android.graphics.BitmapFactory
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Mood
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zerotrace.messenger.session.ChatMessage
import com.zerotrace.messenger.session.Conversation
import com.zerotrace.messenger.session.MessageKind
import com.zerotrace.messenger.session.MsgStatus
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.theme.ChatColors
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import kotlin.math.absoluteValue

fun formatChatTime(ts: Long): String {
    val now = Calendar.getInstance()
    val then = Calendar.getInstance().apply { timeInMillis = ts }
    return when {
        now.get(Calendar.YEAR) == then.get(Calendar.YEAR) &&
            now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR) ->
            SimpleDateFormat("h:mm a", Locale.getDefault()).format(Date(ts))
        now.get(Calendar.YEAR) == then.get(Calendar.YEAR) &&
            now.get(Calendar.DAY_OF_YEAR) - then.get(Calendar.DAY_OF_YEAR) == 1 -> "Yesterday"
        now.get(Calendar.YEAR) == then.get(Calendar.YEAR) ->
            SimpleDateFormat("dd/MM", Locale.getDefault()).format(Date(ts))
        else -> SimpleDateFormat("dd/MM/yy", Locale.getDefault()).format(Date(ts))
    }
}

private val AvatarPalette = listOf(
    Color(0xFF2E7D32), Color(0xFF1565C0), Color(0xFF6A1B9A), Color(0xFFEF6C00),
    Color(0xFF00897B), Color(0xFFC62828), Color(0xFF5D4037), Color(0xFF455A64)
)

fun avatarColor(name: String): Color =
    AvatarPalette[(name.hashCode().absoluteValue) % AvatarPalette.size]

fun initials(name: String): String {
    val parts = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    return when {
        parts.isEmpty() -> "?"
        parts.size == 1 -> parts[0].take(2).uppercase(Locale.getDefault())
        else -> "${parts[0].first()}${parts[1].first()}".uppercase(Locale.getDefault())
    }
}

@Composable
fun ContactAvatar(name: String, size: Int = 48, onClick: (() -> Unit)? = null) {
    Box(
        modifier = Modifier
            .size(size.dp)
            .clip(CircleShape)
            .background(avatarColor(name))
            .let { if (onClick != null) it.clickable { onClick() } else it },
        contentAlignment = Alignment.Center
    ) {
        Text(initials(name), color = Color.White, fontWeight = FontWeight.Bold, fontSize = (size / 3).sp)
    }
}

@Composable
fun ZeroTraceTopBar(
    title: String,
    subtitle: String? = null,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {}
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (onBack != null) {
            IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, contentDescription = "Back") }
        }
        Column(Modifier.weight(1f).padding(start = 4.dp)) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 18.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            subtitle?.let { Text(it, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis) }
        }
        actions()
    }
}

/**
 * Security badge. Green ONLY when the identity has actually been verified
 * (QR commitment + bundle verification). Never green for an assumption.
 */
@Composable
fun SecureStatusBadge(verified: Boolean, live: Boolean) {
    val (icon, text, color) = when {
        verified && live -> Triple(Icons.Filled.Shield, "Verified · Live", MaterialTheme.colorScheme.primary)
        verified -> Triple(Icons.Filled.Shield, "Verified", MaterialTheme.colorScheme.onSurfaceVariant)
        else -> Triple(Icons.Filled.Shield, "Unverified", Color(0xFFF59E0B))
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(14.dp))
        Spacer(Modifier.width(4.dp))
        Text(text, fontSize = 12.sp, color = color)
    }
}

@Composable
fun EmptyState(icon: ImageVector, title: String, body: String, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    Column(
        Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(16.dp))
        Text(title, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Spacer(Modifier.height(8.dp))
        Text(body, fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (actionLabel != null && onAction != null) {
            Spacer(Modifier.height(16.dp))
            androidx.compose.material3.Button(onClick = onAction) { Text(actionLabel) }
        }
    }
}

@Composable
fun LoadingState(text: String) {
    Column(Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator()
        Spacer(Modifier.height(12.dp))
        Text(text, fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun ScreenHeader(title: String, subtitle: String? = null) {
    Text(title, fontSize = 24.sp, fontWeight = FontWeight.Bold)
    subtitle?.let { Text(it, fontSize = 14.sp) }
    Spacer(Modifier.height(16.dp))
}

@Composable
fun ErrorBanner(message: String, onDismiss: () -> Unit) {
    Surface(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        color = MaterialTheme.colorScheme.errorContainer,
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(message, Modifier.weight(1f), fontSize = 14.sp)
            IconButton(onClick = onDismiss) { Icon(Icons.Filled.Close, contentDescription = "Dismiss") }
        }
    }
}

@Composable
fun ErrorBannerHost(vm: ZeroTraceViewModel) {
    val err by vm.lastError.collectAsState()
    err?.let { ErrorBanner(it) { vm.clearError() } }
}

@Composable
fun ChatListItem(conv: Conversation, onClick: () -> Unit) {
    val contact = conv.contact
    Row(
        Modifier.fillMaxWidth().clickable { onClick() }.padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box {
            ContactAvatar(contact.displayName, 52)
            if (conv.hasLiveSession) {
                Box(
                    Modifier.size(12.dp).clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary)
                        .align(Alignment.BottomEnd)
                )
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(contact.displayName, fontWeight = FontWeight.Bold, fontSize = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (conv.pinned) { Icon(Icons.Filled.PushPin, contentDescription = "Pinned", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            val last = conv.lastMessage
            Text(
                when {
                    last != null -> last.preview
                    conv.hasLiveSession -> "Session live — no messages yet"
                    else -> "Tap to start an encrypted session"
                },
                fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(formatChatTime(conv.lastTimeMs), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (conv.muted) Icon(Icons.Filled.VolumeOff, contentDescription = "Muted", modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                if (conv.unread > 0) {
                    Spacer(Modifier.width(4.dp))
                    Box(
                        Modifier.clip(CircleShape)
                            .background(if (conv.muted) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.primary)
                            .padding(horizontal = 7.dp, vertical = 2.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("${conv.unread}", color = if (conv.muted) Color.White else MaterialTheme.colorScheme.onPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MessageBubble(
    msg: ChatMessage,
    isDark: Boolean,
    selected: Boolean,
    onLongPress: () -> Unit,
    onImageClick: (ChatMessage) -> Unit
) {
    val bubbleColor = when {
        selected -> MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
        msg.outgoing -> if (isDark) ChatColors.OutgoingBubble else ChatColors.OutgoingBubbleLight
        else -> if (isDark) ChatColors.IncomingBubble else ChatColors.IncomingBubbleLight
    }
    val shape = RoundedCornerShape(16.dp, 16.dp, if (msg.outgoing) 4.dp else 16.dp, if (msg.outgoing) 16.dp else 4.dp)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 3.dp),
        horizontalArrangement = if (msg.outgoing) Arrangement.End else Arrangement.Start
    ) {
        Surface(
            color = bubbleColor, shape = shape,
            modifier = Modifier.combinedClickable(
                onClick = { if (msg.kind == MessageKind.IMAGE) onImageClick(msg) },
                onLongClick = onLongPress
            )
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                when (msg.kind) {
                    MessageKind.TEXT -> Text(msg.text, fontSize = 15.sp)
                    MessageKind.IMAGE -> {
                        val bmp = remember(msg.id) { msg.fileBytes?.let { BitmapFactory.decodeByteArray(it, 0, it.size) } }
                        if (bmp != null) {
                            Image(bmp.asImageBitmap(), contentDescription = "Photo", Modifier.size(220.dp).clip(RoundedCornerShape(8.dp)))
                        } else Text("📷 Photo (could not be decoded)", fontSize = 15.sp)
                        if (msg.text.isNotBlank()) { Spacer(Modifier.height(4.dp)); Text(msg.text, fontSize = 15.sp) }
                    }
                    MessageKind.FILE -> {
                        Text("📎 ${msg.fileName ?: "File"}", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        Text(formatFileSize(msg.fileSize), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    MessageKind.AUDIO -> {
                        Text("🎵 ${msg.fileName ?: "Audio"}", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        Text(formatFileSize(msg.fileSize), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    MessageKind.VOICE_NOTE -> {
                        Text("🎙 Voice note", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                        Text(formatFileSize(msg.fileSize), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (msg.reactions.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Row { msg.reactions.forEach { (emoji, count) -> Text("$emoji $count  ", fontSize = 13.sp) } }
                }
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.align(Alignment.End)) {
                    Text(
                        SimpleDateFormat("h:mm a", Locale.getDefault()).format(Date(msg.timestampMs)),
                        fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (msg.outgoing) {
                        Spacer(Modifier.width(4.dp))
                        when (msg.status) {
                            MsgStatus.SENDING -> Icon(Icons.Filled.Check, contentDescription = "Sending", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            MsgStatus.SENT -> Icon(Icons.Filled.Check, contentDescription = "Sent", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            MsgStatus.DELIVERED -> Icon(Icons.Filled.DoneAll, contentDescription = "Delivered", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            MsgStatus.READ -> Icon(Icons.Filled.DoneAll, contentDescription = "Read", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
                            MsgStatus.FAILED -> Text("Failed", fontSize = 11.sp, color = MaterialTheme.colorScheme.error)
                            else -> {}
                        }
                    }
                }
            }
        }
    }
}

fun formatFileSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
}

private val CommonEmojis = listOf("❤️", "😂", "👍", "😮", "😢", "🙏", "🔥", "🎉", "👏", "😊", "🤔", "👀")

@Composable
fun MessageComposer(
    enabled: Boolean,
    recording: Boolean,
    onSend: (String) -> Unit,
    onAttach: () -> Unit,
    onCamera: () -> Unit,
    onMicToggle: () -> Unit
) {
    var text by remember { mutableStateOf("") }
    var showEmojis by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp)) {
        if (showEmojis) {
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
                CommonEmojis.forEach { e ->
                    Text(e, fontSize = 24.sp, modifier = Modifier.clickable { text += e })
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = RoundedCornerShape(24.dp), color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 4.dp, end = 4.dp)) {
                    IconButton(onClick = { showEmojis = !showEmojis }, enabled = enabled) {
                        Icon(Icons.Filled.Mood, contentDescription = "Emoji")
                    }
                    OutlinedTextField(
                        value = text, onValueChange = { text = it },
                        placeholder = { Text(if (recording) "Recording voice note…" else "Message") },
                        modifier = Modifier.weight(1f),
                        enabled = enabled && !recording,
                        maxLines = 5
                    )
                    IconButton(onClick = onAttach, enabled = enabled) {
                        Icon(Icons.Filled.AttachFile, contentDescription = "Attach")
                    }
                    IconButton(onClick = onCamera, enabled = enabled) {
                        Icon(Icons.Filled.CameraAlt, contentDescription = "Camera")
                    }
                }
            }
            Spacer(Modifier.width(8.dp))
            if (text.isNotBlank()) {
                IconButton(
                    onClick = { onSend(text); text = "" },
                    enabled = enabled,
                    modifier = Modifier.size(48.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary)
                ) { Icon(Icons.Filled.Send, contentDescription = "Send", tint = MaterialTheme.colorScheme.onPrimary) }
            } else {
                IconButton(
                    onClick = onMicToggle,
                    enabled = enabled,
                    modifier = Modifier.size(48.dp).clip(CircleShape)
                        .background(if (recording) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                ) { Icon(Icons.Filled.Mic, contentDescription = if (recording) "Stop recording" else "Record voice note", tint = Color.White) }
            }
        }
    }
}

@Composable
fun AttachmentSheet(
    onPickImage: () -> Unit,
    onPickDocument: () -> Unit,
    onPickAudio: () -> Unit,
    onDismiss: () -> Unit
) {
    Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Attach", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                IconButton(onClick = onDismiss) { Icon(Icons.Filled.Close, contentDescription = "Close") }
            }
            Spacer(Modifier.height(8.dp))
            AttachmentRow("Photo or video", "Images and videos up to 10 MB, encrypted end-to-end") { onPickImage() }
            AttachmentRow("Document", "PDF, Office files, text and ZIP up to 10 MB") { onPickDocument() }
            AttachmentRow("Audio", "Audio files up to 10 MB") { onPickAudio() }
            Spacer(Modifier.height(8.dp))
            Text(
                "Files are chunked over the live encrypted session. Nothing is saved automatically — the peer accepts each file first.",
                fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AttachmentRow(title: String, subtitle: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onClick() }.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 15.sp)
            Text(subtitle, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Icon(Icons.Filled.MoreVert, contentDescription = null)
    }
}

@Composable
fun SecurityInformationCard(rows: List<Pair<String, String>>) {
    Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.padding(16.dp)) {
            rows.forEachIndexed { i, (k, v) ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(k, fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
                    Spacer(Modifier.width(12.dp))
                    Text(v, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                }
                if (i < rows.lastIndex) Spacer(Modifier.height(10.dp))
            }
        }
    }
}

@Composable
fun ExperimentalNotice(title: String, body: String) {
    Surface(
        Modifier.fillMaxWidth().padding(16.dp),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.tertiaryContainer
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("EXPERIMENTAL — $title", fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Spacer(Modifier.height(8.dp))
            Text(body, fontSize = 14.sp)
        }
    }
}
