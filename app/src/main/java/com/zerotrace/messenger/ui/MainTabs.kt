package com.zerotrace.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zerotrace.messenger.network.TorState
import com.zerotrace.messenger.session.CallDirection
import com.zerotrace.messenger.session.CallKind
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.ChatListItem
import com.zerotrace.messenger.ui.components.ContactAvatar
import com.zerotrace.messenger.ui.components.EmptyState
import com.zerotrace.messenger.ui.components.ErrorBannerHost
import com.zerotrace.messenger.ui.components.ExperimentalNotice
import com.zerotrace.messenger.ui.components.ZeroTraceTopBar
import com.zerotrace.messenger.ui.components.formatChatTime

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainTabs(vm: ZeroTraceViewModel) {
    val tab by vm.currentTab.collectAsState()
    val tor by vm.torState.collectAsState()
    var fabMenu by remember { mutableStateOf(false) }
    var showGroupPlanned by remember { mutableStateOf(false) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == Tab.CHATS, onClick = { vm.goTab(Tab.CHATS) },
                    icon = { Icon(Icons.Filled.Chat, contentDescription = "Chats") }, label = { Text("Chats") }
                )
                NavigationBarItem(
                    selected = tab == Tab.UPDATES, onClick = { vm.goTab(Tab.UPDATES) },
                    icon = { Icon(Icons.Filled.Group, contentDescription = "Updates") }, label = { Text("Updates") }
                )
                NavigationBarItem(
                    selected = tab == Tab.CALLS, onClick = { vm.goTab(Tab.CALLS) },
                    icon = { Icon(Icons.Filled.Call, contentDescription = "Calls") }, label = { Text("Calls") }
                )
                NavigationBarItem(
                    selected = false, onClick = { vm.go(Screen.SETTINGS) },
                    icon = { Icon(Icons.Filled.MoreVert, contentDescription = "Settings") }, label = { Text("Settings") }
                )
            }
        },
        floatingActionButton = {
            if (tab == Tab.CHATS) {
                FloatingActionButton(onClick = { fabMenu = true }) {
                    Icon(Icons.Filled.Add, contentDescription = "New")
                }
                DropdownMenu(expanded = fabMenu, onDismissRequest = { fabMenu = false }) {
                    DropdownMenuItem(text = { Text("Add contact (scan QR)") }, onClick = { fabMenu = false; vm.go(Screen.ADD_CONTACT) })
                    DropdownMenuItem(text = { Text("New group") }, onClick = { fabMenu = false; showGroupPlanned = true })
                    DropdownMenuItem(text = { Text("My pairing QR") }, onClick = { fabMenu = false; vm.go(Screen.MY_IDENTITY) })
                }
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            ZeroTraceTopBar(
                title = "ZeroTrace",
                subtitle = "Tor: ${tor.userLabel}",
                actions = {
                    IconButton(onClick = { vm.lockAndDisconnect() }) {
                        Icon(Icons.Filled.Lock, contentDescription = "Secure lock")
                    }
                }
            )
            ErrorBannerHost(vm)
            when (tab) {
                Tab.CHATS -> ChatsTab(vm)
                Tab.UPDATES -> UpdatesTab(vm)
                Tab.CALLS -> CallsTab(vm)
                Tab.SETTINGS -> ChatsTab(vm) // Settings opens as its own screen; unreachable here.
            }
        }
    }
    if (showGroupPlanned) {
        AlertDialog(
            onDismissRequest = { showGroupPlanned = false },
            title = { Text("Groups — planned") },
            text = {
                Text(
                    "Group messaging needs a reviewed group end-to-end encryption protocol " +
                        "(for example MLS). Reusing the one-to-one ratchet for a group would be " +
                        "incorrect and insecure, so groups stay disabled until that protocol " +
                        "exists and is tested."
                )
            },
            confirmButton = { TextButton(onClick = { showGroupPlanned = false }) { Text("OK") } }
        )
    }
}

@Composable
fun ChatsTab(vm: ZeroTraceViewModel) {
    val conversations by vm.conversations.collectAsState()
    val contacts by vm.contacts.collectAsState()
    var query by remember { mutableStateOf("") }
    var unreadOnly by remember { mutableStateOf(false) }
    val list = conversations.values
        .filter { !it.contact.blocked }
        .filter { if (unreadOnly) it.unread > 0 else true }
        .filter { query.isBlank() || it.contact.displayName.contains(query, ignoreCase = true) }
        .sortedWith(compareByDescending<com.zerotrace.messenger.session.Conversation> { it.pinned }.thenByDescending { it.lastTimeMs })
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            placeholder = { Text("Search chats") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            singleLine = true
        )
        Row(Modifier.padding(horizontal = 16.dp)) {
            androidx.compose.material3.FilterChip(
                selected = !unreadOnly, onClick = { unreadOnly = false }, label = { Text("All") }
            )
            Spacer(Modifier.padding(4.dp))
            androidx.compose.material3.FilterChip(
                selected = unreadOnly, onClick = { unreadOnly = true }, label = { Text("Unread") }
            )
        }
        Spacer(Modifier.height(8.dp))
        if (contacts.isEmpty()) {
            EmptyState(
                icon = Icons.Filled.Chat,
                title = "No contacts yet",
                body = "ZeroTrace has no central directory. Add someone by scanning their pairing QR in person — that is how identities are verified.",
                actionLabel = "Add contact",
                onAction = { vm.go(Screen.ADD_CONTACT) }
            )
        } else if (list.isEmpty()) {
            EmptyState(icon = Icons.Filled.Search, title = "No chats match", body = "Try a different search, or clear the Unread filter.")
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(list, key = { it.contact.onionAddress }) { conv ->
                    ChatListItem(conv) { vm.openChat(conv.contact) }
                }
            }
        }
    }
}

@Composable
fun UpdatesTab(vm: ZeroTraceViewModel) {
    val conversations by vm.conversations.collectAsState()
    val myStatus by vm.myStatusText.collectAsState()
    var editing by remember { mutableStateOf(false) }
    var draft by remember { mutableStateOf("") }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("My Status", fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                ContactAvatar(vm.myDisplayName.value.ifBlank { "Me" }, 52)
                Spacer(Modifier.padding(6.dp))
                Column(Modifier.weight(1f)) {
                    Text(if (myStatus.isBlank()) "No live status" else myStatus, maxLines = 2)
                    Text(
                        "Live-only: visible to connected peers while you are online. Nothing is stored anywhere.",
                        fontSize = 12.sp, color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            if (editing) {
                OutlinedTextField(
                    value = draft, onValueChange = { draft = it },
                    placeholder = { Text("Write a status (280 chars)…") },
                    modifier = Modifier.fillMaxWidth()
                )
                Row {
                    TextButton(onClick = { vm.setMyStatus(draft, null); editing = false }) { Text("Publish live") }
                    TextButton(onClick = { editing = false }) { Text("Cancel") }
                }
            } else {
                Row {
                    TextButton(onClick = { draft = myStatus; editing = true }) { Text(if (myStatus.isBlank()) "Set status" else "Edit status") }
                    if (myStatus.isNotBlank()) TextButton(onClick = { vm.clearMyStatus() }) { Text("Delete") }
                }
            }
            Spacer(Modifier.height(16.dp))
            Text("Recent updates", fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
        }
        val withStatus = conversations.values.filter { it.peerStatus != null }
        if (withStatus.isEmpty()) {
            item {
                EmptyState(
                    icon = Icons.Filled.Group,
                    title = "No live updates",
                    body = "A contact's status appears here only while you have a live encrypted session with them. Statuses are never stored or relayed — when the session ends, the status disappears."
                )
            }
        } else {
            items(withStatus, key = { it.contact.onionAddress }) { conv ->
                val st = conv.peerStatus!!
                Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    ContactAvatar(conv.contact.displayName, 52)
                    Spacer(Modifier.padding(6.dp))
                    Column(Modifier.weight(1f)) {
                        Text(conv.contact.displayName, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                        Text(st.text, maxLines = 2)
                        Text(formatChatTime(st.timestampMs), fontSize = 12.sp, color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { vm.openChat(conv.contact) }) { Text("Reply") }
                }
            }
        }
    }
}

@Composable
fun CallsTab(vm: ZeroTraceViewModel) {
    val records by vm.callRecords.collectAsState()
    val contacts by vm.contacts.collectAsState()
    var pickContact by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        ExperimentalNotice(
            title = "Voice calls are experimental",
            body = "Voice calls run over Tor onion services (TCP) with Opus audio and a " +
                "fresh per-call encryption key — no media server, no TURN, no direct IP. " +
                "Expect noticeable delay and occasional audio gaps: Tor routing is slow. " +
                "Video calling is not built yet. Only real calls are recorded here, in RAM only."
        )
        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = androidx.compose.foundation.layout.Arrangement.SpaceBetween, verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Text("Call history", fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            TextButton(onClick = { pickContact = true }) { Text("New call") }
        }
        if (records.isEmpty()) {
            EmptyState(icon = Icons.Filled.Call, title = "No calls yet", body = "Call attempts are recorded here in RAM only. No call metadata is ever stored on disk.")
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(records, key = { it.id }) { r ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        ContactAvatar(r.displayName, 48)
                        Spacer(Modifier.padding(6.dp))
                        Column(Modifier.weight(1f)) {
                            Text(r.displayName, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                            Text(
                                "${if (r.kind == CallKind.VOICE) "Voice" else "Video"} · ${r.direction.name.lowercase()} · ${formatChatTime(r.timestampMs)}",
                                fontSize = 13.sp, color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            val outcomeText = when (r.outcome) {
                                "connected" -> "Connected · ${r.durationSeconds}s"
                                "missed" -> "Missed"
                                "declined" -> "Declined"
                                else -> "Failed"
                            }
                            Text(outcomeText, fontSize = 12.sp, color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        IconButton(onClick = {
                            contacts.firstOrNull { it.onionAddress == r.contactOnion }?.let { vm.attemptCall(it, r.kind) }
                        }) { Icon(if (r.kind == CallKind.VOICE) Icons.Filled.Call else Icons.Filled.Videocam, contentDescription = "Call again") }
                    }
                }
            }
        }
    }
    if (pickContact) {
        AlertDialog(
            onDismissRequest = { pickContact = false },
            title = { Text("Choose a contact") },
            text = {
                Column {
                    if (contacts.isEmpty()) Text("No contacts yet — add one by scanning their pairing QR.")
                    contacts.forEach { c ->
                        TextButton(onClick = { pickContact = false; vm.attemptCall(c, CallKind.VOICE) }) { Text("Voice — ${c.displayName}") }
                        TextButton(onClick = { pickContact = false; vm.attemptCall(c, CallKind.VIDEO) }) { Text("Video — ${c.displayName}") }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { pickContact = false }) { Text("Cancel") } }
        )
    }
}
