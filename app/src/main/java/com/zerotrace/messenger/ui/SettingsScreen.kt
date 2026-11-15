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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import com.zerotrace.messenger.network.TorState
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.ErrorBannerHost
import com.zerotrace.messenger.ui.components.SecurityInformationCard
import com.zerotrace.messenger.ui.components.ZeroTraceTopBar
import com.zerotrace.messenger.ui.theme.Accent
import com.zerotrace.messenger.ui.theme.ThemeMode

@Composable
fun SettingsScreen(vm: ZeroTraceViewModel) {
    val timeout by vm.sessionTimeoutMinutes.collectAsState()
    val themeMode by vm.themeMode.collectAsState()
    val accent by vm.accent.collectAsState()
    val myName by vm.myDisplayName.collectAsState()
    val appLock by vm.appLockEnabled.collectAsState()
    val conversations by vm.conversations.collectAsState()
    var editName by remember { mutableStateOf(false) }
    var draftName by remember { mutableStateOf("") }
    var confirmDelete by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        ZeroTraceTopBar(title = "Settings", onBack = { vm.goTab(Tab.CHATS) })
        ErrorBannerHost(vm)
        Column(Modifier.padding(16.dp)) {
            Text("Profile", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("Display name: ${myName.ifBlank { "(not set — your onion address is your identity)" }}")
            Row {
                TextButton(onClick = { draftName = myName; editName = true }) { Text(if (myName.isBlank()) "Set display name" else "Change display name") }
                TextButton(onClick = { vm.go(Screen.MY_IDENTITY) }) { Text("My pairing QR") }
            }
            if (editName) {
                OutlinedTextField(value = draftName, onValueChange = { draftName = it }, label = { Text("Display name (local only)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Row {
                    TextButton(onClick = { vm.setMyDisplayName(draftName); editName = false }) { Text("Save") }
                    TextButton(onClick = { editName = false }) { Text("Cancel") }
                }
            }

            Spacer(Modifier.height(16.dp))
            Text("Privacy & security", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { vm.go(Screen.DASHBOARD) }, Modifier.fillMaxWidth()) { Text("Security dashboard — real status of every component") }
            Spacer(Modifier.height(8.dp))
            Text("Session timeout: $timeout minutes (idle sessions end and wipe automatically)")
            Row {
                listOf(5, 10, 30).forEach { m ->
                    TextButton(onClick = { vm.setSessionTimeout(m) }) { Text("$m") }
                }
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("App lock (device PIN)")
                    Text("Asks for your device PIN/pattern/password when the app opens. Takes effect on next launch.", fontSize = 12.sp)
                }
                Switch(checked = appLock, onCheckedChange = { vm.setAppLock(it) })
            }
            Text("Screenshot protection: always on (FLAG_SECURE on every screen). Notification previews: always hidden — notifications never contain message content, names or fingerprints. Copied text: cleared from the clipboard after 30 seconds.", fontSize = 13.sp)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { vm.lockAndDisconnect() }, Modifier.fillMaxWidth()) { Text("Emergency lock — disconnect & wipe all sessions") }

            Spacer(Modifier.height(16.dp))
            Text("Notifications", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("ZeroTrace has no push infrastructure (no Firebase/FCM) by design. While a session is live, a foreground notification shows only \"Encrypted session running\" — never content. There are no message sounds; unread counts appear in the chat list.", fontSize = 13.sp)

            Spacer(Modifier.height(16.dp))
            Text("Storage & data", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            val liveSessions = conversations.values.count { it.hasLiveSession }
            val ramMessages = conversations.values.sumOf { it.messages.size }
            SecurityInformationCard(
                listOf(
                    "Contacts stored" to "${conversations.size} (encrypted)",
                    "Live sessions" to "$liveSessions",
                    "Messages in RAM" to "$ramMessages",
                    "Messages on disk" to "0 — RAM only",
                    "Backup" to "Disabled"
                )
            )
            Spacer(Modifier.height(8.dp))
            Text("Data retention: messages exist only in volatile memory and are wiped when their session ends, when the app is locked, or when the process dies. Nothing is kept for later.", fontSize = 13.sp)

            Spacer(Modifier.height(16.dp))
            Text("Appearance", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("Theme")
            Row {
                ThemeMode.values().forEach { m ->
                    TextButton(onClick = { vm.setThemeMode(m) }) {
                        Text(m.name.lowercase().replaceFirstChar { it.uppercase() } + if (themeMode == m) " ✓" else "")
                    }
                }
            }
            Text("Accent colour")
            Row {
                Accent.values().forEach { a ->
                    TextButton(onClick = { vm.setAccent(a) }) {
                        Text(a.label + if (accent == a) " ✓" else "")
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
            Text("About", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(8.dp))
            Text("ZeroTrace Messenger v0.2.0-experimental. Private communication. No central server. No persistent conversations.", fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            Text("Security architecture: post-quantum identity (ML-DSA-87) and key agreement (ML-KEM-1024), Double Ratchet + per-step ML-KEM, Tor onion services via Arti. Full details: docs/THREAT_MODEL.md, docs/CRYPTOGRAPHIC_PROTOCOL.md, docs/LIMITATIONS.md in the project.", fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            Text("Limitations (honest): the PQ handshake is experimental and unaudited; live Tor messaging has not been tested on two physical devices; calls are not implemented; groups are planned, not built. See the Security Dashboard for the real status of each component.", fontSize = 13.sp)
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = { confirmDelete = true }, Modifier.fillMaxWidth()) { Text("Delete local identity") }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete local identity?") },
            text = { Text("This deletes your identity, all contacts and all sessions from this device. It cannot be undone — there is no cloud copy to restore from.") },
            confirmButton = {
                TextButton(onClick = { confirmDelete = false; vm.deleteIdentity(); vm.go(Screen.ONBOARDING) }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } }
        )
    }
}

@Composable
fun DashboardScreen(vm: ZeroTraceViewModel) {
    val tor by vm.torState.collectAsState()
    val level by vm.keystoreLevel.collectAsState()
    val core by vm.coreAvailable.collectAsState()
    val test by vm.selfTest.collectAsState()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        ZeroTraceTopBar(title = "Security dashboard", subtitle = "Only real status is shown. Nothing here is green for an unimplemented feature.", onBack = { vm.go(Screen.SETTINGS) })
        Column(Modifier.padding(16.dp)) {
            SecurityInformationCard(
                listOf(
                    "Rust core" to if (core) "Loaded" else "NOT LOADED — encryption unavailable",
                    "Crypto self-test" to test,
                    "Keystore level" to level.name,
                    "Tor state" to tor.userLabel,
                    "Onion service" to if (tor == TorState.ONION_SERVICE_READY || tor == TorState.E2EE_SESSION_READY) "Ready" else "Not ready",
                    "E2EE session" to if (tor.isReady) "Ready" else "Not ready",
                    "PQ handshake" to "EXPERIMENTAL — PQXDH-Sync v1, no independent review",
                    "Ratchet" to "EXPERIMENTAL — Double Ratchet + per-step ML-KEM; braid absent",
                    "Tor / Arti" to "EXPERIMENTAL — not tested on two physical devices",
                    "File transfer" to "Live — chunked over the ratchet, SHA-256 verified, 10 MB cap",
                    "Voice notes" to "Live — recorded to RAM via pipe, no temp file",
                    "Calls" to "EXPERIMENTAL — voice only over Tor (v0.3.0); video planned; media AEAD unreviewed",
                    "Groups" to "PLANNED — needs a reviewed group protocol (MLS)",
                    "Message storage" to "RAM only — nothing persisted",
                    "Backup" to "Disabled (allowBackup=false)"
                )
            )
        }
    }
}
