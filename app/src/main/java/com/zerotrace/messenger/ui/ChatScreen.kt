package com.zerotrace.messenger.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Reply
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import com.zerotrace.messenger.network.TorState
import com.zerotrace.messenger.session.CallKind
import com.zerotrace.messenger.session.ChatMessage
import com.zerotrace.messenger.session.MessageKind
import com.zerotrace.messenger.session.MsgStatus
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.WireFrame
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.AttachmentSheet
import com.zerotrace.messenger.ui.components.ContactAvatar
import com.zerotrace.messenger.ui.components.EmptyState
import com.zerotrace.messenger.ui.components.ErrorBannerHost
import com.zerotrace.messenger.ui.components.MessageBubble
import com.zerotrace.messenger.ui.components.MessageComposer
import com.zerotrace.messenger.ui.components.SecureStatusBadge
import com.zerotrace.messenger.ui.components.SecurityInformationCard
import com.zerotrace.messenger.ui.components.formatFileSize
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(vm: ZeroTraceViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val activeOnion by vm.activeOnion.collectAsState()
    val conversations by vm.conversations.collectAsState()
    val conv = activeOnion?.let { conversations[it] }
    val tor by vm.torState.collectAsState()
    val incomingOffers by vm.incomingOffers.collectAsState()
    val outgoingProgress by vm.outgoingProgress.collectAsState()
    val themeMode by vm.themeMode.collectAsState()
    val isDark = when (themeMode) {
        com.zerotrace.messenger.ui.theme.ThemeMode.DARK -> true
        com.zerotrace.messenger.ui.theme.ThemeMode.LIGHT -> false
        com.zerotrace.messenger.ui.theme.ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

    var selected by remember { mutableStateOf<ChatMessage?>(null) }
    var replyTo by remember { mutableStateOf<ChatMessage?>(null) }
    var showAttach by remember { mutableStateOf(false) }
    var showCamera by remember { mutableStateOf(false) }
    var showSearch by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var showSecurity by remember { mutableStateOf(false) }
    var showInfo by remember { mutableStateOf<ChatMessage?>(null) }
    var previewImage by remember { mutableStateOf<ChatMessage?>(null) }
    var menuExpanded by remember { mutableStateOf(false) }
    var recording by remember { mutableStateOf(false) }
    var savePending by remember { mutableStateOf<ChatMessage?>(null) }
    val recorder = remember { VoiceRecorder() }

    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val msg = savePending
        savePending = null
        if (uri != null && msg?.fileBytes != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { it.write(msg.fileBytes) }
            }
        }
    }
    val pickImages = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        uris.forEach { uri -> sendPickedFile(context, vm, uri) }
    }
    val pickDocuments = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        uris.forEach { uri -> sendPickedFile(context, vm, uri) }
    }
    val micPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) recording = recorder.start()
    }

    if (conv == null) {
        LaunchedEffect(Unit) { vm.goTab(com.zerotrace.messenger.session.Tab.CHATS) }
        return
    }
    val contact = conv.contact
    LaunchedEffect(conv.contact.onionAddress) { vm.markChatRead(conv) }

    if (showCamera) {
        CameraScreen(
            onCaptured = { bytes ->
                showCamera = false
                vm.sendFile("photo.jpg", bytes, "image/jpeg", "image")
            },
            onClose = { showCamera = false }
        )
        return
    }

    Column(Modifier.fillMaxSize()) {
        // Top bar
        Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { vm.goTab(com.zerotrace.messenger.session.Tab.CHATS) }) {
                Icon(Icons.Filled.Close, contentDescription = "Back to chats")
            }
            ContactAvatar(contact.displayName, 40) { vm.go(Screen.CONTACT_PROFILE) }
            Spacer(Modifier.padding(4.dp))
            Column(Modifier.weight(1f)) {
                Text(contact.displayName, fontWeight = FontWeight.Bold)
                Text(
                    when {
                        conv.hasLiveSession -> "Live encrypted session"
                        tor == TorState.ONION_SERVICE_READY -> "Tap to connect — peer must be online"
                        else -> tor.userLabel
                    },
                    fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (selected != null) {
                IconButton(onClick = { replyTo = selected; selected = null }) { Icon(Icons.Filled.Reply, contentDescription = "Reply") }
                IconButton(onClick = {
                    selected?.let {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("message", it.text))
                        scope.launch {
                            delay(30_000)
                            cm.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                    }
                    selected = null
                }) { Icon(Icons.Filled.ContentCopy, contentDescription = "Copy (cleared after 30s)") }
                IconButton(onClick = { showInfo = selected; selected = null }) { Icon(Icons.Filled.Info, contentDescription = "Message info") }
                IconButton(onClick = { selected?.let { vm.deleteMessage(it) }; selected = null }) { Icon(Icons.Filled.Delete, contentDescription = "Delete") }
            } else {
                IconButton(onClick = { vm.attemptCall(contact, CallKind.VOICE) }) { Icon(Icons.Filled.Call, contentDescription = "Voice call") }
                IconButton(onClick = { vm.attemptCall(contact, CallKind.VIDEO) }) { Icon(Icons.Filled.Videocam, contentDescription = "Video call") }
                IconButton(onClick = { menuExpanded = true }) { Icon(Icons.Filled.MoreVert, contentDescription = "More") }
                DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                    DropdownMenuItem(text = { Text("View contact") }, onClick = { menuExpanded = false; vm.go(Screen.CONTACT_PROFILE) })
                    DropdownMenuItem(text = { Text("Search in chat") }, onClick = { menuExpanded = false; showSearch = true })
                    DropdownMenuItem(text = { Text(if (conv.muted) "Unmute" else "Mute") }, onClick = { menuExpanded = false; vm.setMuted(conv, !conv.muted) })
                    DropdownMenuItem(text = { Text("Security info") }, onClick = { menuExpanded = false; showSecurity = true })
                    DropdownMenuItem(text = { Text("End session — wipe messages") }, onClick = {
                        menuExpanded = false
                        vm.endSession(contact)
                        vm.goTab(com.zerotrace.messenger.session.Tab.CHATS)
                    })
                }
            }
        }
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            SecureStatusBadge(verified = true, live = conv.hasLiveSession)
            Spacer(Modifier.padding(4.dp))
            Text("End-to-end encrypted · Tor · RAM only", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (showSearch) {
            OutlinedTextField(
                value = searchQuery, onValueChange = { searchQuery = it },
                placeholder = { Text("Search in this chat") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = { IconButton(onClick = { showSearch = false; searchQuery = "" }) { Icon(Icons.Filled.Close, contentDescription = "Close search") } },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                singleLine = true
            )
        }
        ErrorBannerHost(vm)

        // Incoming file offers
        incomingOffers.values.filter { it.first == contact.onionAddress }.forEach { (_, offer) ->
            androidx.compose.material3.Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text("Incoming file: ${offer.name} (${formatFileSize(offer.size)})", fontWeight = FontWeight.Bold)
                    Text("From ${contact.displayName}. Accept to receive it encrypted into memory — nothing is saved automatically.", fontSize = 13.sp)
                    Row {
                        TextButton(onClick = { vm.acceptIncomingFile(offer.fileId) }) { Text("Accept") }
                        TextButton(onClick = { vm.declineIncomingFile(offer.fileId) }) { Text("Decline") }
                    }
                }
            }
        }

        // Messages
        val visible = conv.messages.filter {
            searchQuery.isBlank() || it.text.contains(searchQuery, ignoreCase = true) ||
                (it.fileName?.contains(searchQuery, ignoreCase = true) == true)
        }
        if (visible.isEmpty()) {
            Box(Modifier.weight(1f)) {
                EmptyState(
                    icon = Icons.Filled.Info,
                    title = if (conv.hasLiveSession) "Session is live" else "No live session",
                    body = if (conv.hasLiveSession)
                        "Messages are end-to-end encrypted and exist only in memory. They disappear when this session ends."
                    else
                        "Both of you must be online at the same time. Tap below to connect over Tor."
                )
            }
        } else {
            val listState = rememberLazyListState()
            LazyColumn(Modifier.weight(1f), state = listState, reverseLayout = true) {
                items(visible.reversed(), key = { it.id }) { msg ->
                    MessageBubble(
                        msg = msg, isDark = isDark,
                        selected = selected?.id == msg.id,
                        onLongPress = { selected = if (selected?.id == msg.id) null else msg },
                        onImageClick = { previewImage = it }
                    )
                }
            }
        }

        // Outgoing transfer progress
        outgoingProgress.values.firstOrNull()?.let { (sent, total) ->
            if (total > 0) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
                    Text("Sending file… ${formatFileSize(sent)} / ${formatFileSize(total)}", fontSize = 12.sp)
                    LinearProgressIndicator(progress = { sent.toFloat() / total.toFloat() }, modifier = Modifier.fillMaxWidth())
                }
            }
        }

        // Reply preview
        replyTo?.let { r ->
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Replying to: ${r.preview.take(60)}", fontSize = 13.sp, modifier = Modifier.weight(1f))
                IconButton(onClick = { replyTo = null }) { Icon(Icons.Filled.Close, contentDescription = "Cancel reply") }
            }
        }

        if (!conv.hasLiveSession) {
            androidx.compose.material3.Button(
                onClick = { vm.openChat(contact) },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                enabled = tor == TorState.ONION_SERVICE_READY
            ) { Text(if (tor == TorState.ONION_SERVICE_READY) "Connect — start encrypted session" else "Waiting for Tor… (${tor.userLabel})") }
        }
        MessageComposer(
            enabled = conv.hasLiveSession,
            recording = recording,
            onSend = { text -> vm.sendMessage(text, replyTo?.id); replyTo = null },
            onAttach = { showAttach = true },
            onCamera = { showCamera = true },
            onMicToggle = {
                if (recording) {
                    recording = false
                    val bytes = recorder.stop()
                    if (bytes != null) vm.sendFile("voice-note.3gp", bytes, "audio/3gpp", "voice")
                } else {
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                        recording = recorder.start()
                    } else micPermission.launch(Manifest.permission.RECORD_AUDIO)
                }
            }
        )
        Text(
            "Messages live only in memory. Ending the session wipes this conversation.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp)
        )
    }

    if (showAttach) {
        ModalBottomSheet(onDismissRequest = { showAttach = false }) {
            AttachmentSheet(
                onPickImage = { showAttach = false; pickImages.launch(arrayOf("image/*", "video/*")) },
                onPickDocument = { showAttach = false; pickDocuments.launch(arrayOf("*/*")) },
                onPickAudio = { showAttach = false; pickDocuments.launch(arrayOf("audio/*")) },
                onDismiss = { showAttach = false }
            )
        }
    }

    if (showSecurity) {
        AlertDialog(
            onDismissRequest = { showSecurity = false },
            title = { Text("Conversation security") },
            text = {
                Column {
                    SecurityInformationCard(
                        listOf(
                            "Encryption" to "End-to-end · ChaCha20-Poly1305",
                            "Key agreement" to "X25519 + ML-KEM-1024",
                            "Identity" to "Ed25519 + ML-DSA-87",
                            "Fingerprint" to contact.fingerprint.take(35) + "…",
                            "Tor state" to tor.userLabel,
                            "Session" to if (conv.hasLiveSession) "Live" else "Not connected",
                            "Storage" to "RAM only — nothing persisted",
                            "Handshake" to "PQXDH-Sync v1 (experimental)"
                        )
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Compare the fingerprint with your contact in person. If it ever changes unexpectedly, do not continue — re-verify before trusting the conversation.",
                        fontSize = 13.sp
                    )
                }
            },
            confirmButton = { TextButton(onClick = { showSecurity = false }) { Text("Close") } }
        )
    }

    showInfo?.let { msg ->
        AlertDialog(
            onDismissRequest = { showInfo = null },
            title = { Text("Message info") },
            text = {
                Text(
                    "Type: ${msg.kind}\nStatus: ${msg.status}\n" +
                        "Time: ${java.text.SimpleDateFormat("dd MMM yyyy, h:mm a", java.util.Locale.getDefault()).format(java.util.Date(msg.timestampMs))}\n" +
                        (msg.fileName?.let { "File: $it (${formatFileSize(msg.fileSize)})\n" } ?: "") +
                        "Encrypted with the live session ratchet. No delivery receipt exists for messages sent before the peer connected."
                )
            },
            confirmButton = { TextButton(onClick = { showInfo = null }) { Text("Close") } }
        )
    }

    previewImage?.let { msg ->
        Dialog(onDismissRequest = { previewImage = null }) {
            Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, androidx.compose.foundation.shape.RoundedCornerShape(16.dp)).padding(12.dp)) {
                val bmp = remember(msg.id) { msg.fileBytes?.let { BitmapFactory.decodeByteArray(it, 0, it.size) } }
                if (bmp != null) Image(bmp.asImageBitmap(), contentDescription = "Photo", Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { previewImage = null }) { Text("Close") }
                    TextButton(onClick = { savePending = msg; saveLauncher.launch(msg.fileName ?: "photo.jpg") }) { Text("Save…") }
                }
            }
        }
    }
}

private fun sendPickedFile(context: Context, vm: ZeroTraceViewModel, uri: Uri) {
    try {
        val resolver = context.contentResolver
        var name = "file"
        var size = 0L
        resolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                if (nameIdx >= 0) name = c.getString(nameIdx) ?: name
                if (sizeIdx >= 0) size = c.getLong(sizeIdx)
            }
        }
        val mime = resolver.getType(uri) ?: guessMime(name)
        val bytes = resolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0L
            var n: Int
            while (input.read(buf).also { n = it } >= 0) {
                total += n
                if (total > WireFrame.MAX_FILE_BYTES) return // too big: refuse, never send partial
                out.write(buf, 0, n)
            }
            out.toByteArray()
        } ?: return
        if (size > 0 && size != bytes.size.toLong()) return
        val kind = when {
            mime.startsWith("image/") -> "image"
            mime.startsWith("audio/") -> "audio"
            else -> "file"
        }
        vm.sendFile(name, bytes, mime, kind)
    } catch (_: Exception) {
        // Reading failed: refuse silently, never send a partial file.
    }
}

private fun guessMime(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
    "jpg", "jpeg" -> "image/jpeg"
    "png" -> "image/png"
    "webp" -> "image/webp"
    "gif" -> "image/gif"
    "mp4" -> "video/mp4"
    "mp3" -> "audio/mpeg"
    "pdf" -> "application/pdf"
    "txt" -> "text/plain"
    "zip" -> "application/zip"
    else -> "application/octet-stream"
}
