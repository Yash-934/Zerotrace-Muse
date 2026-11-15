package com.zerotrace.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zerotrace.messenger.session.CallKind
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.ContactAvatar
import com.zerotrace.messenger.ui.components.ErrorBannerHost
import com.zerotrace.messenger.ui.components.SecureStatusBadge
import com.zerotrace.messenger.ui.components.SecurityInformationCard
import com.zerotrace.messenger.ui.components.ZeroTraceTopBar

@Composable
fun ContactProfileScreen(vm: ZeroTraceViewModel) {
    val activeOnion by vm.activeOnion.collectAsState()
    val conversations by vm.conversations.collectAsState()
    val conv = activeOnion?.let { conversations[it] }
    var renaming by remember { mutableStateOf(false) }
    var draftName by remember { mutableStateOf("") }
    var confirmBlock by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }

    if (conv == null) {
        vm.goTab(Tab.CHATS)
        return
    }
    val contact = conv.contact
    val sharedMedia = conv.messages.filter { it.kind == com.zerotrace.messenger.session.MessageKind.IMAGE || it.kind == com.zerotrace.messenger.session.MessageKind.FILE }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        ZeroTraceTopBar(title = "Contact info", onBack = { vm.go(Screen.CHAT) })
        ErrorBannerHost(vm)
        Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            ContactAvatar(contact.displayName, 96)
            Spacer(Modifier.height(12.dp))
            Text(contact.displayName, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            Text(if (conv.hasLiveSession) "Live session" else "Not connected", fontSize = 14.sp)
            Spacer(Modifier.height(8.dp))
            SecureStatusBadge(verified = true, live = conv.hasLiveSession)
            Spacer(Modifier.height(16.dp))
            Row {
                IconButton(onClick = { vm.attemptCall(contact, CallKind.VOICE) }) {
                    Icon(Icons.Filled.Call, contentDescription = "Voice call")
                }
                IconButton(onClick = { vm.attemptCall(contact, CallKind.VIDEO) }) {
                    Icon(Icons.Filled.Videocam, contentDescription = "Video call")
                }
                IconButton(onClick = { vm.openChat(contact) }) {
                    Icon(Icons.Filled.Search, contentDescription = "Search in conversation")
                }
                IconButton(onClick = { draftName = contact.displayName; renaming = true }) {
                    Icon(Icons.Filled.Edit, contentDescription = "Rename (local only)")
                }
            }
            Spacer(Modifier.height(8.dp))
            Text("About this contact", fontWeight = FontWeight.Bold, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
            SecurityInformationCard(
                listOf(
                    "Onion address" to (contact.onionAddress.take(24) + "…"),
                    "Fingerprint" to contact.fingerprint,
                    "Identity key" to (contact.identityEd25519.take(24) + "…"),
                    "Added" to java.text.SimpleDateFormat("dd MMM yyyy", java.util.Locale.getDefault())
                        .format(java.util.Date(contact.addedEpochSeconds * 1000)),
                    "Messages" to "${conv.messages.size} in memory (RAM only)"
                )
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "Fingerprint verification: compare this fingerprint with your contact in person or over a channel you already trust. If it changes without explanation, stop and re-verify — never accept a new identity silently.",
                fontSize = 13.sp
            )
            Spacer(Modifier.height(16.dp))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Mute notifications", modifier = Modifier.weight(1f))
                Switch(checked = conv.muted, onCheckedChange = { vm.setMuted(conv, it) })
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Pin conversation", modifier = Modifier.weight(1f))
                Switch(checked = conv.pinned, onCheckedChange = { vm.setPinned(conv, it) })
            }
            Spacer(Modifier.height(16.dp))
            Text("Shared media & files (${sharedMedia.size})", fontWeight = FontWeight.Bold, modifier = Modifier.fillMaxWidth())
            if (sharedMedia.isEmpty()) {
                Text("No files shared yet in this session. Shared files exist only in memory while the session is live.", fontSize = 13.sp)
            } else {
                sharedMedia.forEach { m ->
                    Text("• ${m.fileName ?: m.kind} — ${com.zerotrace.messenger.ui.components.formatFileSize(m.fileSize)}", fontSize = 13.sp, modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp))
                }
            }
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = { confirmBlock = true }, Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.Block, contentDescription = null)
                Text(if (contact.blocked) "Unblock contact" else "Block contact")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { confirmRemove = true }, Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.Delete, contentDescription = null)
                Text("Remove contact")
            }
            Spacer(Modifier.height(8.dp))
            Button(onClick = { vm.openChat(contact) }, Modifier.fillMaxWidth()) { Text("Open chat") }
        }
    }

    if (renaming) {
        AlertDialog(
            onDismissRequest = { renaming = false },
            title = { Text("Rename contact") },
            text = {
                Column {
                    Text("This name is stored only on your device, in the encrypted contact store.")
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(value = draftName, onValueChange = { draftName = it }, label = { Text("Display name") }, singleLine = true)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    vm.renameContact(contact, draftName)
                    renaming = false
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { renaming = false }) { Text("Cancel") } }
        )
    }
    if (confirmBlock) {
        AlertDialog(
            onDismissRequest = { confirmBlock = false },
            title = { Text(if (contact.blocked) "Unblock contact?" else "Block contact?") },
            text = { Text(if (contact.blocked) "They will be able to reach you again." else "Their bundles and handshakes will be ignored, and any live session ends immediately.") },
            confirmButton = {
                TextButton(onClick = { vm.blockContact(contact, !contact.blocked); confirmBlock = false }) { Text(if (contact.blocked) "Unblock" else "Block") }
            },
            dismissButton = { TextButton(onClick = { confirmBlock = false }) { Text("Cancel") } }
        )
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text("Remove contact?") },
            text = { Text("This deletes the verified contact from the encrypted store and ends any live session. You will need to scan their QR again to talk to them.") },
            confirmButton = {
                TextButton(onClick = {
                    vm.removeContact(contact)
                    confirmRemove = false
                    vm.goTab(Tab.CHATS)
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("Cancel") } }
        )
    }
}
